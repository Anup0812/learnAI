"""
health_monitor_app_sched.py - Native Windows service wrapper around the schedulers.

Location
--------
This file lives in the APPASSIST project ROOT (next to main_app.py,
database.py and the modules/ package). That matters: the service must be
able to ``import database`` and ``import modules.application_health_check``
/ ``import modules.mimp_report``. Those packages resolve only when the
project root is on sys.path, so the root is exactly where this script
belongs. (It used to live under modules/application_health_check/, where
BASE_DIR pointed at the sub-folder and those imports could not resolve.)

Uses pywin32 (which ships with Anaconda) to register the schedulers as a
real Windows service - shows up in services.msc, controllable with
`net start` / `net stop`, automatically restarted by the Service Control
Manager on crash.

No third-party tools required. No NSSM, no srvany, nothing to install.

What the service does
---------------------
On start:
  1. Forces both sweeps to a 30-minute cadence (SWEEP_INTERVAL_MINUTES
     below) by seeding HEALTH_SWEEP_INTERVAL_MIN / MIMP_SWEEP_INTERVAL_SEC
     BEFORE the scheduler modules are imported (those read the interval
     at import time).
  2. Loads .env (if present) so SCM-spawned processes pick up DB / SMTP
     credentials that normally come from the user shell.
  3. Calls database.init_db() to ensure the schema and indexes exist.
  4. Calls health_monitor.init_health_monitoring() which starts an
     APScheduler BackgroundScheduler running TWO jobs:
        - The sweep job (every 30 min) -- finds reports whose
          next_run_time has elapsed and runs them.
        - The retention purge (daily at 02:00 local) -- deletes
          HealthCheckExecution rows older than 5 days.
  5. Initialises MIMP monitoring under a Flask app-context. Its sweep
     (also every 30 min) finds MIMP reports whose next execution time
     has elapsed and runs them, plus a daily maintenance job at 02:00.
  6. Blocks waiting for the SCM stop signal, logging an INFO-level
     heartbeat every minute so the log file shows operational signal.

On stop:
  Calls shutdown_health_monitoring() / shutdown_mimp_monitoring() so
  APScheduler's in-flight job (if any) gets a chance to finish and the
  SQLAlchemy job-stores close cleanly. No half-written DB rows.

Both schedulers run in THIS one process. They use SEPARATE jobstore
tables (apscheduler_jobs vs apscheduler_jobs_mimp) so neither loads or
fires the other's jobs.

INSTALL (run from elevated cmd, from the APPASSIST root):
    cd /d C:\\Path\\To\\APPASSIST
    python health_monitor_app_sched.py install

START:
    net start ApplicationDashboardScheduler
        - or -
    python health_monitor_app_sched.py start

STOP:
    net stop ApplicationDashboardScheduler

REMOVE:
    python health_monitor_app_sched.py remove

DEBUG (run in foreground, see exceptions on the console):
    python health_monitor_app_sched.py debug


After `install`, open services.msc and:
    1. Find "Application Dashboard Scheduler"
    2. Properties -> Log On tab -> set the service account that has DB access
       (or "Local System" if it has sufficient DB credentials via env vars).
    3. Properties -> Recovery tab -> set First / Second / Subsequent failures
       to "Restart the Service" with a 1-minute delay.
    4. Properties -> General tab -> Startup type: Automatic (Delayed Start)
       so the service waits until the OS finishes booting before starting.

Avoiding a duplicate sweeper
----------------------------
The Flask app, when alive under IIS, can ALSO start an APScheduler sweep
(via init_health_monitoring() / init_mimp_monitoring() at app boot). The
atomic claim in _claim_report_for_run (health check) and the per-minute
DB lock (MIMP) prevent double-firing, but it is wasteful to have two
sweepers running. To suppress the Flask-side sweepers and let the service
own the schedule, set this env var in your IIS site config:

    DISABLE_INPROC_SCHEDULER=1

main_app.py already honours that var. This service ignores it on purpose
-- it is the dedicated scheduler owner.
"""

import os
import re
import sys
import socket
import datetime
import logging
from logging.handlers import TimedRotatingFileHandler


# ---------------------------------------------------------------------------
# Make sure imports work whether run by SCM or interactively.
# BASE_DIR is the APPASSIST project root (this file lives there), so
# `import database` and `import modules.*` resolve.
# ---------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

# When started by SCM, current directory is C:\Windows\System32. Fix that.
os.chdir(BASE_DIR)


# ---------------------------------------------------------------------------
# Sweep cadence - 30 minutes for BOTH schedulers.
#
# These env vars MUST be seeded before the scheduler modules are imported
# (health_monitor reads HEALTH_SWEEP_INTERVAL_MIN, and mimp_report.scheduler
# reads MIMP_SWEEP_INTERVAL_SEC, at module-import time). setdefault is used
# so an explicitly pre-set OS env var still wins; the later .env load runs
# with override=False, so it cannot lower these back down.
# ---------------------------------------------------------------------------
SWEEP_INTERVAL_MINUTES = 30
os.environ.setdefault('HEALTH_SWEEP_INTERVAL_MIN', str(SWEEP_INTERVAL_MINUTES))
os.environ.setdefault('MIMP_SWEEP_INTERVAL_SEC',   str(SWEEP_INTERVAL_MINUTES * 60))


import win32serviceutil
import win32service
import win32event
import servicemanager


# ---------------------------------------------------------------------------
# Logging - one file per DAY in <BASE_DIR>/logs/scheduler_log/, with files
# older than LOG_RETENTION_DAYS deleted automatically.
#
# Why this layout (it replaced a single ever-growing scheduler.log):
#   - The active day writes to scheduler.log; at local midnight it is renamed
#     to scheduler_<YYYY-MM-DD>.log and a fresh scheduler.log is opened. So
#     each calendar day ends up as its own dated file.
#   - _purge_old_logs() deletes dated files older than LOG_RETENTION_DAYS. It
#     runs at startup AND after every midnight rollover, so cleanup happens
#     both when the service restarts and while it runs for days on end. We do
#     the purge ourselves (TimedRotatingFileHandler's own backupCount is
#     disabled) because we rename rotated files, which its built-in cleanup
#     would no longer recognise.
# ---------------------------------------------------------------------------
LOG_DIR = os.path.join(BASE_DIR, 'logs')
SCHED_LOG_DIR = os.path.join(LOG_DIR, 'scheduler_log')
os.makedirs(SCHED_LOG_DIR, exist_ok=True)
LOG_PATH = os.path.join(SCHED_LOG_DIR, 'scheduler.log')

LOG_RETENTION_DAYS = 5
# Dated files look like scheduler_2026-06-01.log
_DATED_LOG_RE = re.compile(r'^scheduler_(\d{4}-\d{2}-\d{2})\.log$')


def _purge_old_logs():
    """Delete scheduler_<date>.log files older than LOG_RETENTION_DAYS.

    Date is taken from the filename (not mtime), so it is robust against
    file-copy timestamp changes. The active, undated scheduler.log is never
    matched, so it is never removed. Best-effort: any single failure is
    logged and skipped rather than killing the service."""
    cutoff = datetime.date.today() - datetime.timedelta(days=LOG_RETENTION_DAYS)
    try:
        entries = os.listdir(SCHED_LOG_DIR)
    except OSError:
        return
    for name in entries:
        m = _DATED_LOG_RE.match(name)
        if not m:
            continue
        try:
            file_date = datetime.datetime.strptime(m.group(1), '%Y-%m-%d').date()
        except ValueError:
            continue
        if file_date < cutoff:
            try:
                os.remove(os.path.join(SCHED_LOG_DIR, name))
            except OSError:
                # Logger may not be configured yet at first call; ignore.
                pass


class _DailySchedulerHandler(TimedRotatingFileHandler):
    """Daily handler that names rotated files scheduler_<date>.log and purges
    files past the retention window right after each midnight rollover."""

    def doRollover(self):
        super().doRollover()
        _purge_old_logs()


def _dated_namer(default_name):
    # TimedRotatingFileHandler hands us '.../scheduler.log.2026-06-01';
    # turn it into '.../scheduler_2026-06-01.log'.
    directory = os.path.dirname(default_name)
    base, _, date_suffix = os.path.basename(default_name).partition('.log.')
    if date_suffix:
        return os.path.join(directory, f'{base}_{date_suffix}.log')
    return default_name


_handler = _DailySchedulerHandler(
    LOG_PATH,
    when='midnight',
    interval=1,
    backupCount=0,          # our own _purge_old_logs() owns deletion
    encoding='utf-8',
)
_handler.namer = _dated_namer
_handler.setFormatter(logging.Formatter(
    '%(asctime)s - %(levelname)s - %(name)s - %(message)s'
))

_root = logging.getLogger()
_root.setLevel(logging.INFO)
if not any(isinstance(h, TimedRotatingFileHandler) for h in _root.handlers):
    _root.addHandler(_handler)

# Clean out anything already past the retention window at startup.
_purge_old_logs()

logger = logging.getLogger('scheduler_winservice')


# ---------------------------------------------------------------------------
# .env loader -- SCM does not inherit the user shell environment
# ---------------------------------------------------------------------------
def _load_dotenv_if_present() -> None:
    """Best-effort .env loader so the service sees the same env vars the
    Flask app does. Silently skipped if no .env exists or python-dotenv
    is not installed -- the service will then rely on whatever env vars
    the SCM passes through (typically very few)."""
    dotenv_path = os.path.join(BASE_DIR, '.env')
    if not os.path.isfile(dotenv_path):
        logger.info('.env not found at %s -- relying on SCM-provided env.',
                    dotenv_path)
        return
    try:
        from dotenv import load_dotenv  # type: ignore
        load_dotenv(dotenv_path, override=False)
        logger.info('.env loaded from %s', dotenv_path)
    except ImportError:
        # Manual parse fallback so we don't hard-depend on python-dotenv.
        try:
            with open(dotenv_path, 'r', encoding='utf-8') as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith('#') or '=' not in line:
                        continue
                    key, _, value = line.partition('=')
                    key = key.strip()
                    value = value.strip().strip('"').strip("'")
                    if key and key not in os.environ:
                        os.environ[key] = value
            logger.info('.env loaded (manual parse) from %s', dotenv_path)
        except Exception:
            logger.exception('Failed to parse .env at %s -- continuing.',
                             dotenv_path)


# ===========================================================================
# Service class
# ===========================================================================
class SchedulerService(win32serviceutil.ServiceFramework):
    # These three attributes register the service with Windows
    _svc_name_         = "ApplicationDashboardScheduler"
    _svc_display_name_ = "Application Dashboard Scheduler"
    _svc_description_  = ("Runs APScheduler-based background jobs for the "
                          "Application Dashboard - both the Application "
                          "Health Check and MIMP Report sweeps (every 30 "
                          "min), independent of IIS.")

    # 60-second heartbeat -- frequent enough to detect a hang, infrequent
    # enough to keep the log readable.
    HEARTBEAT_SECONDS = 60

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        # Event object the SCM will signal when it wants us to stop
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)
        socket.setdefaulttimeout(60)
        self.running = False

    # -----------------------------------------------------------------------
    # SCM callbacks
    # -----------------------------------------------------------------------
    def SvcStop(self):
        """Called by the SCM when the service is being stopped."""
        logger.info('SvcStop received - shutting down')
        # Tell the SCM we acknowledge the stop and need a moment to
        # tidy up. Without this Windows may kill us at the 30 s mark.
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING, waitHint=30000)
        self.running = False
        win32event.SetEvent(self.stop_event)

    def SvcDoRun(self):
        """Called by the SCM when the service is being started."""
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, ''),
        )
        logger.info('===== Scheduler service starting (PID %s) =====',
                    os.getpid())
        logger.info('Sweep cadence: %d min (HEALTH_SWEEP_INTERVAL_MIN=%s, '
                    'MIMP_SWEEP_INTERVAL_SEC=%s).',
                    SWEEP_INTERVAL_MINUTES,
                    os.environ.get('HEALTH_SWEEP_INTERVAL_MIN'),
                    os.environ.get('MIMP_SWEEP_INTERVAL_SEC'))

        _load_dotenv_if_present()

        try:
            self._start_schedulers()
            self.running = True
            logger.info('Scheduler service running. Waiting for stop signal...')

            # Block here forever (or until stop_event is signalled).
            # APScheduler runs jobs in its own daemon threads, which keep
            # ticking as long as this main thread is alive.
            heartbeat_ms = self.HEARTBEAT_SECONDS * 1000
            tick = 0
            while self.running:
                rc = win32event.WaitForSingleObject(self.stop_event, heartbeat_ms)
                if rc == win32event.WAIT_OBJECT_0:
                    break  # stop signalled
                tick += 1
                # Cheap, low-volume heartbeat. Once every 5 ticks (~5 min)
                # we also log scheduler.get_jobs() counts so the log file
                # documents that the sweep + retention jobs are still
                # registered.
                if tick % 5 == 0:
                    self._log_job_status()
                else:
                    logger.info(
                        'Heartbeat - scheduler service alive (PID %s, tick %d)',
                        os.getpid(), tick,
                    )

        except Exception as e:
            logger.exception('Fatal error in scheduler service: %s', e)
            servicemanager.LogErrorMsg(
                f"Scheduler service crashed: {e}\n"
                f"See {LOG_PATH} for details."
            )
            raise
        finally:
            # Stop APScheduler cleanly. Will let any in-flight job finish
            # (wait=True inside shutdown_health_monitoring is set to
            # False by design so a hung SSH/DB check can't block our stop
            # -- but the SQLAlchemy job-store still flushes).
            self._stop_schedulers()
            logger.info('===== Scheduler service stopped =====')

    # -----------------------------------------------------------------------
    # Actual work
    # -----------------------------------------------------------------------
    def _start_schedulers(self):
        """Initialize the database and start all background schedulers."""
        # Import here, not at module top - so that `install` / `remove` /
        # `debug` commands don't drag in the whole app stack just to register.
        from flask import Flask
        from database import init_db

        app = Flask(__name__)
        app.config['SECRET_KEY'] = os.environ.get('SESSION_SECRET',
                                                  'scheduler-internal')

        logger.info('Initializing database...')
        init_db()

        logger.info('Initializing health monitoring (sweep every %d min)...',
                    SWEEP_INTERVAL_MINUTES)
        from modules.application_health_check.health_monitor import (
            init_health_monitoring,
        )
        init_health_monitoring()

        # MIMP monitoring is best-effort -- if its module is missing or
        # raises, we still want the health-check sweep to keep running.
        try:
            logger.info('Initializing MIMP monitoring (sweep every %d min)...',
                        SWEEP_INTERVAL_MINUTES)
            from modules.mimp_report.scheduler import init_mimp_monitoring
            with app.app_context():
                init_mimp_monitoring(app)
        except Exception:
            logger.exception('MIMP monitoring failed to start -- continuing '
                             'without it.')

        logger.info('All schedulers started successfully')

    def _stop_schedulers(self):
        """Shut down APScheduler cleanly on service stop."""
        try:
            from modules.application_health_check.health_monitor import (
                shutdown_health_monitoring,
            )
            shutdown_health_monitoring()
            logger.info('Health monitoring shut down cleanly.')
        except Exception:
            logger.exception('Error shutting down health monitoring '
                             '(suppressed -- service is stopping anyway).')

        # Attempt to shut down MIMP too if it exposes a hook. Best effort.
        try:
            from modules.mimp_report.scheduler import shutdown_mimp_monitoring  # type: ignore
            shutdown_mimp_monitoring()
            logger.info('MIMP monitoring shut down cleanly.')
        except ImportError:
            pass
        except Exception:
            logger.exception('Error shutting down MIMP monitoring (suppressed).')

    def _log_job_status(self):
        """Periodic operational snapshot: which jobs are registered and
        when they're next due, for BOTH schedulers. Helps confirm at a
        glance that the sweeps are still alive."""
        self._log_one_scheduler(
            'modules.application_health_check.health_monitor', '_scheduler',
            'health-check',
        )
        self._log_one_scheduler(
            'modules.mimp_report.scheduler', '_scheduler', 'MIMP',
        )

    def _log_one_scheduler(self, module_path: str, attr: str, label: str):
        try:
            import importlib
            mod = importlib.import_module(module_path)
            scheduler = getattr(mod, attr, None)
            if scheduler is None or not getattr(scheduler, 'running', False):
                logger.warning('Heartbeat: %s APScheduler is NOT running.', label)
                return
            jobs = scheduler.get_jobs()
            summary = ', '.join(
                f"{j.id}@{j.next_run_time.strftime('%H:%M:%S') if j.next_run_time else 'idle'}"
                for j in jobs
            ) or 'no jobs'
            logger.info('Heartbeat (PID %s) [%s]: %d job(s): %s',
                        os.getpid(), label, len(jobs), summary)
        except Exception:
            logger.exception('Heartbeat job-status check crashed for %s '
                             '(suppressed).', label)


# ===========================================================================
# Entry point - dispatches install / start / stop / remove / debug
# ===========================================================================
if __name__ == '__main__':
    if len(sys.argv) == 1:
        # Started by the Service Control Manager (no CLI args) - run as service
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(SchedulerService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        # Called from the command line (install / start / stop / debug / remove)
        win32serviceutil.HandleCommandLine(SchedulerService)
