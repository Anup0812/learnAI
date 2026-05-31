from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from auth import get_current_user, require_auth
from database import get_db_session
from .models import FileMonitorReport, FlowType, SystemType
from .utils import test_connectivity, encrypt_password, decrypt_password, get_file_flow_data
from datetime import datetime, timedelta
import json
import logging

# Create blueprint
file_monitor_bp = Blueprint('file_monitor', __name__, template_folder='templates')

# Hard cap on the dashboard date window. The dashboard is intentionally public
# (guests can view reports), so an unbounded range would let any visitor place
# arbitrarily large query / SFTP-scan load on the monitored production systems.
# This is the maximum number of inclusive days a single view may request.
MAX_DATE_RANGE_DAYS = 15

@file_monitor_bp.route('/')
def index():
    """File Monitor System module index page"""
    user = get_current_user()
    
   
    db_session = get_db_session()
    try:
        # Get all active reports grouped by application
        reports = db_session.query(FileMonitorReport).filter_by(is_active=True).all()
       
        # Group reports by application name (case-insensitive)
        app_reports = {}
        for report in reports:
            app_name_lower = report.application_name.lower()
            if app_name_lower not in app_reports:
                app_reports[app_name_lower] = {
                    'name': report.application_name,
                    'summary': report.short_summary,
                    'inbound': None,
                    'outbound': None
                }
           
            if report.flow_type == FlowType.INBOUND:
                app_reports[app_name_lower]['inbound'] = report
            elif report.flow_type == FlowType.OUTBOUND:
                app_reports[app_name_lower]['outbound'] = report
       
        return render_template('file_monitor/index.html',
                             user=user,
                             app_reports=app_reports.values())
    finally:
        db_session.close()

@file_monitor_bp.route('/reports')
def report_list():
    """List all reports for admin users"""
    user = get_current_user()
    if not user or user.role != 'admin':
        flash('Admin access required', 'error')
        return redirect(url_for('file_monitor.index'))
   
    db_session = get_db_session()
    try:
        reports = db_session.query(FileMonitorReport).filter_by(is_active=True).order_by(
            FileMonitorReport.application_name, FileMonitorReport.flow_type
        ).all()
       
        return render_template('file_monitor/report_list.html', user=user, reports=reports)
    finally:
        db_session.close()

@file_monitor_bp.route('/create', methods=['GET', 'POST'])
def create_report():
    """Create new file monitor report"""
    user = get_current_user()
    if not user or user.role != 'admin':
        flash('Admin access required', 'error')
        return redirect(url_for('file_monitor.index'))
   
    if request.method == 'POST':
        try:
            db_session = get_db_session()
           
            # Check for duplicate
            existing = db_session.query(FileMonitorReport).filter_by(
                application_name=request.form.get('application_name'),
                flow_type=FlowType(request.form.get('flow_type')),
                is_active=True
            ).first()
           
            if existing:
                flash('Report already exists for this application and flow type', 'error')
                return render_template('file_monitor/create_report.html', user=user)
           
            # Create new report
            report = FileMonitorReport(
                application_name=request.form.get('application_name'),
                short_summary=request.form.get('short_summary'),
                flow_type=FlowType(request.form.get('flow_type')),
               
                # Source system
                source_name=request.form.get('source_name'),
                source_system_type=SystemType(request.form.get('source_system_type'))
                #intermediate_name=request.form.get('intermediate_name'),
                #intermediate_system_type=SystemType(request.form.get('intermediate_system_type')),
                #target_name=request.form.get('target_name'),
                #target_system_type=SystemType(request.form.get('target_system_type'))
            )
           
           
            # Set source system specific fields
            if report.source_system_type in [SystemType.ORACLE, SystemType.MSSQL]:
                report.source_connection_string = encrypt_password(request.form.get('source_connection_string', ''))
                report.source_username = request.form.get('source_username')
                report.source_password = encrypt_password(request.form.get('source_password', ''))
                report.source_sql_query = request.form.get('source_sql_query')
                report.source_filename_column = request.form.get('source_filename_column')
                report.source_primary_stats_column = request.form.get('source_primary_stats_column')
                report.source_secondary_stats_column = request.form.get('source_secondary_stats_column')
                report.source_date_format = request.form.get('source_date_format')
               
                #excluded_values = request.form.get('source_excluded_values', '').strip()
                #if excluded_values:
                #    report.source_excluded_values = json.dumps([v.strip() for v in excluded_values.split(',') if v.strip()])
           
            elif report.source_system_type == SystemType.LOG:
                report.source_hostname = request.form.get('source_hostname')
                report.source_path = request.form.get('source_path')
                report.source_sftp_username = request.form.get('source_sftp_username')
                report.source_sftp_password = encrypt_password(request.form.get('source_sftp_password', ''))
                report.source_file_naming_convention = request.form.get('source_file_naming_convention')
                report.source_extraction_pattern = request.form.get('source_extraction_pattern')
                report.source_data_split=request.form.get('source_data_split')
                report.source_data_fileName=request.form.get('source_data_fileName')
                report.source_stats_pattern = request.form.get('source_stats_pattern')
                #report.source_excluded_pattern = request.form.get('source_excluded_pattern')
                report.source_date_format = request.form.get('source_date_format')
           
            # Handle intermediate system
            report.has_intermediate = 'has_intermediate' in request.form
            if report.has_intermediate:
                report.intermediate_name = request.form.get('intermediate_name')
                report.intermediate_system_type = SystemType(request.form.get('intermediate_system_type'))
               
                if report.intermediate_system_type in [SystemType.ORACLE, SystemType.MSSQL]:
                    report.intermediate_connection_string = encrypt_password(request.form.get('intermediate_connection_string', ''))
                    report.intermediate_username = request.form.get('intermediate_username')
                    report.intermediate_password = encrypt_password(request.form.get('intermediate_password', ''))
                    report.intermediate_sql_query = request.form.get('intermediate_sql_query')
                    report.intermediate_filename_column = request.form.get('intermediate_filename_column')
                    report.intermediate_primary_stats_column = request.form.get('intermediate_primary_stats_column')
                    report.intermediate_secondary_stats_column = request.form.get('intermediate_secondary_stats_column')
                    #report.intermediate_excluded_column = request.form.get('intermediate_excluded_column')
                    report.intermediate_date_format = request.form.get('intermediate_date_format')
                    #excluded_values = request.form.get('intermediate_excluded_values', '').strip()
                    #if excluded_values:
                    #    report.intermediate_excluded_values = json.dumps([v.strip() for v in excluded_values.split(',') if v.strip()])
               
                elif report.intermediate_system_type == SystemType.LOG:
                    report.intermediate_hostname = request.form.get('intermediate_hostname')
                    report.intermediate_path = request.form.get('intermediate_path')
                    report.intermediate_sftp_username = request.form.get('intermediate_sftp_username')
                    report.intermediate_sftp_password = encrypt_password(request.form.get('intermediate_sftp_password', ''))
                    report.intermediate_file_naming_convention = request.form.get('intermediate_file_naming_convention')
                    report.intermediate_extraction_pattern = request.form.get('intermediate_extraction_pattern')
                    report.intermediate_data_split=request.form.get('intermediate_data_split')
                    report.intermediate_data_fileName=request.form.get('intermediate_data_fileName')
                    report.intermediate_stats_pattern = request.form.get('intermediate_stats_pattern')
                    #report.intermediate_excluded_pattern = request.form.get('intermediate_excluded_pattern')
                    report.intermediate_date_format = request.form.get('intermediate_date_format')
           
            # Target system
            report.target_name = request.form.get('target_name')
            report.target_system_type = SystemType(request.form.get('target_system_type'))
           
            if report.target_system_type in [SystemType.ORACLE, SystemType.MSSQL]:
                report.target_connection_string = encrypt_password(request.form.get('target_connection_string', ''))
                report.target_username = request.form.get('target_username')
                report.target_password = encrypt_password(request.form.get('target_password', ''))
                report.target_sql_query = request.form.get('target_sql_query')
                report.target_filename_column = request.form.get('target_filename_column')
                report.target_primary_stats_column = request.form.get('target_primary_stats_column')
                report.target_secondary_stats_column = request.form.get('target_secondary_stats_column')
                #report.target_excluded_column = request.form.get('target_excluded_column')
                report.target_date_format = request.form.get('target_date_format')
                #excluded_values = request.form.get('target_excluded_values', '').strip()
                #if excluded_values:
                #    report.target_excluded_values = json.dumps([v.strip() for v in excluded_values.split(',') if v.strip()])
           
            elif report.target_system_type == SystemType.LOG:
                report.target_hostname = request.form.get('target_hostname')
                report.target_path = request.form.get('target_path')
                report.target_sftp_username = request.form.get('target_sftp_username')
                report.target_sftp_password = encrypt_password(request.form.get('target_sftp_password', ''))
                report.target_file_naming_convention = request.form.get('target_file_naming_convention')
                report.target_extraction_pattern = request.form.get('target_extraction_pattern')
                report.target_data_split=request.form.get('target_data_split')
                report.target_data_fileName=request.form.get('target_data_fileName')
                report.target_stats_pattern = request.form.get('target_stats_pattern')
                #report.target_excluded_pattern = request.form.get('target_excluded_pattern')
                report.target_date_format = request.form.get('target_date_format')
               
           
            # Exclusion sets apply regardless of source type (DB or SFTP/log)
            report.exclude_data = request.form.get('exclude_data')
            report.exclude_data1 = request.form.get('exclude_data1')

            db_session.add(report)
            db_session.commit()
           
            flash('Report created successfully', 'success')
            return redirect(url_for('file_monitor.index'))
           
        except Exception as e:
            db_session.rollback()
            logging.error(f"Error creating report: {str(e)}")
            flash('Error creating report', 'error')
        finally:
            db_session.close()
   
    return render_template('file_monitor/create_report.html', user=user)

@file_monitor_bp.route('/dashboard/<int:report_id>')
def dashboard(report_id):
    """Display dashboard for a specific report"""
    user = get_current_user()
    
    logging.info(f"Loading file-monitor dashboard for report_id={report_id}")

    # Date range from query params. Default window = last 1 day. Both values are
    # parsed defensively (this route is public, so a guest may pass anything) and
    # the span is hard-capped at MAX_DATE_RANGE_DAYS to bound the load on the
    # monitored production databases / SFTP servers.
    today = datetime.now()
    default_end = today.strftime('%Y-%m-%d')
    default_start = (today - timedelta(days=1)).strftime('%Y-%m-%d')

    def _parse_date(value, fallback):
        try:
            return datetime.strptime(value, '%Y-%m-%d')
        except (TypeError, ValueError):
            return datetime.strptime(fallback, '%Y-%m-%d')

    end_dt = _parse_date(request.args.get('end_date'), default_end)
    start_dt = _parse_date(request.args.get('start_date'), default_start)

    # Normalise ordering, then enforce the maximum window. A clamped window keeps
    # the most recent MAX_DATE_RANGE_DAYS days (inclusive) ending at end_date.
    if start_dt > end_dt:
        start_dt = end_dt
    if (end_dt - start_dt).days >= MAX_DATE_RANGE_DAYS:
        start_dt = end_dt - timedelta(days=MAX_DATE_RANGE_DAYS - 1)
        flash(f'Date range limited to the most recent {MAX_DATE_RANGE_DAYS} days.', 'warning')

    start_date = start_dt.strftime('%Y-%m-%d')
    end_date = end_dt.strftime('%Y-%m-%d')

    db_session = get_db_session()
    
    try:
        report = db_session.query(FileMonitorReport).filter_by(id=report_id, is_active=True).first()
        if not report:
            flash('Report not found', 'error')
            return redirect(url_for('file_monitor.index'))
        source_date_format=report.source_date_format
        intermediate_date_format=report.intermediate_date_format
        target_date_format=report.target_date_format
        if source_date_format:
            s_date_format=source_date_format
        else:
            s_date_format=None
        if intermediate_date_format:
            i_date_format=intermediate_date_format
        else:
            i_date_format=None
        if target_date_format:
            t_date_format=target_date_format
        else:
            t_date_format=None
            
       
        # Get file flow data
        metrics=None
        dataframes=None
        plots=None
        try:
            logging.debug('This is a DEBUG message')
            logging.error(f"tdate: {t_date_format}")
            metrics,dataframes,plots = get_file_flow_data(report, s_date_format,start_date, end_date,i_date_format,t_date_format)
            

            #metrics=analysis_results['metrics']
            #dataframe=analysis_results['dataframe']
            #plots=analysis_results['plots']
            

            #source data metric 
            total_source=metrics['total_source_records']
            pending_source=metrics['pending_at_source_count']
            pending_source_pct=metrics['pending_at_source_percent']
            # analyze_file_transfers nests the pending frame under
            # source_table['pending'] — there is no top-level 'pending_source'
            # key, so the previous lookup raised KeyError on every successful
            # fetch and silently blanked the whole dashboard.
            pending_source_df=dataframes['source_table']['pending']
            logging.error(f"total_source: {total_source}")
            logging.error(f"pending_source: {pending_source}")
            
            
        except Exception as e:
            logging.error(f"Error getting flow data: {str(e)}")
            total_source=0
            pending_source=0
            pending_source_pct=0
            pending_source_df=None
            error=str(e)
       
       
        return render_template('file_monitor/dashboard.html',
                             user=user,
                             report=report,
                             metrics=metrics,
                             dataframes=dataframes,
                             plots=plots,
                             start_date=start_date,
                             end_date=end_date,
                             total_source=total_source,
                             pending_source=pending_source,
                             pending_source_pct=pending_source_pct,
                             pending_source_df=pending_source_df
                             
                             )
    finally:
        db_session.close()

@file_monitor_bp.route('/test-connectivity', methods=['POST'])
def test_connectivity_route():
    """Test connectivity for system configuration"""
    user = get_current_user()
    if not user or user.role != 'admin':
        return jsonify({'success': False, 'message': 'Admin access required'})
   
    try:
        system_type = request.json.get('system_type')
        config = request.json.get('config', {})
       
        result = test_connectivity(system_type, config)
        return jsonify(result)
       
    except Exception as e:
        logging.error(f"Connectivity test error: {str(e)}")
        return jsonify({'success': False, 'message': str(e)})

@file_monitor_bp.route('/delete/<int:report_id>', methods=['POST'])
def delete_report(report_id):
    """Delete a report (admin only)"""
    user = get_current_user()
    if not user or user.role != 'admin':
        flash('Admin access required', 'error')
        return redirect(url_for('file_monitor.index'))
   
    db_session = get_db_session()
    try:
        report = db_session.query(FileMonitorReport).filter_by(id=report_id).first()
        if report:
            report.is_active = False
            db_session.commit()
            flash('Report deleted successfully', 'success')
        else:
            flash('Report not found', 'error')
    except Exception as e:
        db_session.rollback()
        logging.error(f"Error deleting report: {str(e)}")
        flash('Error deleting report', 'error')
    finally:
        db_session.close()

    return redirect(url_for('file_monitor.report_list'))


@file_monitor_bp.route('/about')
def about():
    """About page — explains the module to end users and the support team."""
    user = get_current_user()
    return render_template('file_monitor/about.html', user=user)
