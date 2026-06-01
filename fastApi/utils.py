import os
import pandas as pd
from datetime import datetime, timedelta
import logging
import json
from crypto_utils import encrypt_data, decrypt_data
import re
import plotly.graph_objects as go
import plotly.io as pio


# The Oracle (cx_Oracle), SQL Server (pyodbc) and SSH/SFTP (paramiko) drivers are
# imported LAZILY, never at module load. Each depends on native libraries (the
# Oracle Instant Client / an ODBC driver / cryptography back-ends) that may be
# absent on a given host. Importing them at the top would make this whole module
# fail to import — which would break blueprint registration in main_app.py and
# stop the ENTIRE application from starting. Loading them only when a probe
# actually needs them keeps a missing driver a per-report problem instead of a
# site-wide outage. (The MIMP probes already follow this same pattern.)
def _import_cx_oracle():
    import cx_Oracle
    return cx_Oracle


def _import_pyodbc():
    import pyodbc
    return pyodbc


def _import_paramiko():
    import paramiko
    return paramiko


def encrypt_password(password):
    """Encrypt password for storage"""
    if not password:
        return ''
    return encrypt_data(password)


def decrypt_password(encrypted_password):
    """Decrypt password for use"""
    if not encrypted_password:
        return ''
    return decrypt_data(encrypted_password)


def test_connectivity(system_type, config):
    """Test connectivity to a system"""
    try:
        if system_type in ['oracle', 'mssql']:
            return test_database_connectivity(system_type, config)
        elif system_type == 'log':
            return test_sftp_connectivity(config)
        else:
            return {'success': False, 'message': 'Unknown system type'}
    except Exception as e:
        logging.error(f"Connectivity test failed: {str(e)}")
        return {'success': False, 'message': str(e)}


def test_database_connectivity(system_type, config):
    """Test database connectivity"""
    connection_string = config.get('connection_string', '')
    username = config.get('username', '')
    password = config.get('password', '')
    test_query = config.get('test_query', 'SELECT 1 FROM DUAL' if system_type == 'oracle' else 'SELECT 1')

    conn = None
    try:
        if system_type == 'oracle':
            cx_Oracle = _import_cx_oracle()
            # Try to establish Oracle connection. NOTE: cx_Oracle has no
            # connect-level timeout argument — to bound a connect to a dead
            # host, put CONNECT_TIMEOUT in the TNS/easy-connect string.
            # call_timeout below bounds a slow/hung test QUERY once connected.
            conn = cx_Oracle.connect(username, password, connection_string)
            try:
                conn.call_timeout = 15000  # ms
            except Exception:
                pass
            cursor = conn.cursor()
            cursor.execute(test_query)
            result = cursor.fetchone()
            cursor.close()

            return {'success': True, 'message': 'Oracle connection successful'}

        elif system_type == 'mssql':
            pyodbc = _import_pyodbc()
            # `timeout` bounds the LOGIN attempt so a wrong/dead host cannot pin
            # the worker at the OS TCP timeout; conn.timeout bounds the query.
            conn = pyodbc.connect(connection_string, timeout=15)
            try:
                conn.timeout = 15  # per-statement query timeout (s)
            except Exception:
                pass
            cursor = conn.cursor()
            cursor.execute(test_query)
            result = cursor.fetchone()
            cursor.close()

            return {'success': True, 'message': 'SQL Server connection successful'}

    except ImportError as e:
        return {'success': False, 'message': f'Database driver not available: {str(e)}'}
    except Exception as e:
        return {'success': False, 'message': f'Connection failed: {str(e)}'}
    finally:
        # Always release the connection, even when the test query raised.
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def test_sftp_connectivity(config):
    """Test SFTP connectivity"""
    hostname = config.get('hostname', '')
    username = config.get('username', '')
    password = config.get('password', '')
    path = config.get('path', '/')

    try:
        paramiko = _import_paramiko()
        # Create SSH client
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # Connect
        ssh.connect(hostname, username=username, password=password, timeout=10)

        # Test SFTP
        sftp = ssh.open_sftp()
        sftp.listdir(path)
        sftp.close()
        ssh.close()

        return {'success': True, 'message': 'SFTP connection successful'}

    except ImportError as e:
        return {'success': False, 'message': 'Paramiko library not available'}
    except Exception as e:
        return {'success': False, 'message': f'SFTP connection failed: {str(e)}'}


def _apply_exclusion(df, exclude_spec):
    """Split *df* into (kept, excluded) using a single comma-separated exclude spec.

    A spec is either exact values ("a.usr,b.usr") or a wildcard ("*.usr" / "tmp*").
    The matching column is auto-detected. This is intentionally NON-fatal: an empty
    spec, an unsupported wildcard, or a spec that matches no column simply excludes
    nothing (returns the frame unchanged) instead of raising and blanking the report.
    """
    excluded = df.iloc[0:0].copy()  # empty frame with the same columns
    if not exclude_spec or df.empty:
        return df, excluded

    exclude_values = [v.strip() for v in str(exclude_spec).split(',') if v.strip()]
    if not exclude_values:
        return df, excluded

    first_val = exclude_values[0]
    if '*' not in first_val:
        match_type = 'exact'                 # e.g. report.usr,audit.usr
    elif first_val.startswith('*') and first_val.endswith('*') and len(first_val) > 2:
        match_type = 'contains'              # e.g. *temp*  → drop anything containing "temp"
    elif first_val.startswith('*'):
        match_type = 'endswith'              # e.g. *.usr   → drop by extension/suffix
    elif first_val.endswith('*'):
        match_type = 'startswith'            # e.g. tmp_*   → drop by prefix
    else:
        logging.warning(f"Unsupported wildcard format '{first_val}' in exclusion; skipping.")
        return df, excluded

    def _condition(series):
        s = series.astype(str)
        if match_type == 'exact':
            return s.isin(exclude_values)
        if match_type == 'startswith':
            return s.str.startswith(tuple(v[:-1] for v in exclude_values))
        if match_type == 'endswith':
            return s.str.endswith(tuple(v[1:] for v in exclude_values))
        # contains: value matches if it holds any of the inner tokens
        tokens = [v.strip('*') for v in exclude_values if v.strip('*')]
        if not tokens:
            return pd.Series(False, index=s.index)
        return s.str.contains('|'.join(re.escape(t) for t in tokens), na=False, regex=True)

    # Auto-detect the column the pattern applies to
    matched_column = None
    for col in df.columns:
        if _condition(df[col]).any():
            matched_column = col
            break

    if matched_column is None:
        logging.info(f"Exclusion values {exclude_values} matched no column; nothing excluded.")
        return df, excluded

    condition = _condition(df[matched_column])
    excluded = df[condition].copy()
    kept = df[~condition].copy()
    return kept, excluded


def analyze_file_transfers(source_df, target_df, inter_df=None, exclude_data=None, exclude_data1=None):
    # Defensive: upstream getters may return None on a hard failure. Coerce to
    # empty frames so the analysis degrades gracefully instead of crashing.
    if source_df is None:
        source_df = _empty_file_df()
    if target_df is None:
        target_df = _empty_file_df()

    metrics = {}
    dataframes = {}
    plots = {}
    df_exclude = pd.DataFrame()

    def generate_combined_stat_plot(df, df_name, top_n=20):
        data = []
        buttons = []

        for col in ['primary_stat', 'secondary_stat']:
            if col in df.columns and df[col].notna().any():
                value_counts = df[col].value_counts().nlargest(top_n).reset_index()
                value_counts.columns = ['stat_value', 'count']

                bar = go.Bar(
                    x=value_counts['stat_value'],
                    y=value_counts['count'],
                    name=col,
                    visible=False,
                    text=value_counts['count'],
                    textposition='outside',
                    hovertemplate='<b>%{x}</b><br>Count: %{y}',
                    marker=dict(color='rgba(58, 71, 80, 0.6)')
                )
                data.append(bar)

                visibility = [False] * len(data)
                visibility[-1] = True

                buttons.append(dict(
                    label=col,
                    method='update',
                    args=[{'visible': visibility}, {'title': f'{col} Distribution in {df_name}'}]
                ))

        if not data:
            return None

        data[0].visible = True

        layout = go.Layout(
            title=f'{data[0].name} Distribution in {df_name}',
            xaxis=dict(title='Stat Value', tickangle=-45),
            yaxis=dict(title='Count'),
            updatemenus=[{
                'buttons': buttons,
                'direction': 'down',
                'showactive': True,
                'x': 0.5,
                'y': 1.2,
                'xanchor': 'center'
            }],
            height=500,
            template='plotly_white',
            margin=dict(t=80)
        )

        fig = go.Figure(data=data, layout=layout)
        return pio.to_html(fig, full_html=False)

    def generate_processed_records_grouped_bar(data_dict):
        combined_df = []

        for system_name, df in data_dict.items():
            if df is None or df.empty or 'SENT_DATE' not in df.columns:
                continue

            df = df.copy()
            df['SENT_DATE'] = pd.to_datetime(df['SENT_DATE'], errors='coerce')
            df = df.dropna(subset=['SENT_DATE'])

            if df.empty:
                continue

            df['date'] = df['SENT_DATE'].dt.date
            grouped = df.groupby('date').size().reset_index(name='count')
            grouped['system'] = system_name
            combined_df.append(grouped)

        if not combined_df:
            return None

        full_df = pd.concat(combined_df)

        data = []
        systems = full_df['system'].unique()
        colors = {'source': 'rgba(0, 123, 255, 0.7)', 'intermediate': 'rgba(40, 167, 69, 0.7)',
                  'target': 'rgba(220, 53, 69, 0.7)'}

        for system in systems:
            df_sys = full_df[full_df['system'] == system]
            trace = go.Bar(
                x=df_sys['date'],
                y=df_sys['count'],
                name=system.capitalize(),
                marker_color=colors.get(system, 'gray'),
                hovertemplate="<b>%{x}</b><br>%{y} records<extra>%{fullData.name}</extra>"
            )
            data.append(trace)

        layout = go.Layout(
            barmode='group',
            title='Processed Records Per Day by System',
            xaxis=dict(title='Date'),
            yaxis=dict(title='Record Count'),
            template='plotly_white',
            height=500,
            margin=dict(t=80)
        )

        fig = go.Figure(data=data, layout=layout)
        return pio.to_html(fig, full_html=False)

    def check_and_generate_plots(df, df_name):
        plot_html = generate_combined_stat_plot(df, df_name)
        if plot_html:
            plots[f'{df_name}_stat_dropdown_plot'] = plot_html

    # Generate stat plots
    check_and_generate_plots(source_df, 'source')
    check_and_generate_plots(target_df, 'target')
    if inter_df is not None and not inter_df.empty:
        check_and_generate_plots(inter_df, 'intermediate')

    # Source Stats
    total_source = len(source_df)

    # ── Exclusion logic (supports two independent sets) ─────────────────────
    # Some file types are produced at the source but, by application design, are
    # never meant to reach the destination. They are filtered out of the transfer
    # tracking here and surfaced separately as "Excluded Files" rather than being
    # mis-counted as "pending at source".
    df_exclude = source_df.iloc[0:0].copy()  # empty, same columns as source
    for spec in (exclude_data, exclude_data1):
        source_df, ex = _apply_exclusion(source_df, spec)
        if not ex.empty:
            df_exclude = pd.concat([df_exclude, ex], ignore_index=True)
    # ────────────────────────────────────────────────────────────────────────

    # ── Source counts, kept unambiguous so source vs destination never confuse ──
    #   total_source  = every record seen at the source
    #   excluded      = removed by design (never meant to reach the destination)
    #   eligible      = total − excluded = the files that SHOULD reach the destination
    # All transfer percentages below are measured against ELIGIBLE, not total, so a
    # large set of by-design exclusions can't drag the "delivered %" down.
    metrics['total_source_records'] = total_source
    metrics['excluded_source_records'] = len(df_exclude)
    eligible_source = len(source_df)  # source_df has already had exclusions removed
    metrics['eligible_source_records'] = eligible_source

    # --- UPDATED DUPLICATE FILE LOGIC (Date-Aware) ---
    # Use "|||" as the separator so filenames containing underscores never
    # corrupt the date portion when we split the composite key later.
    _SEP = "|||"

    def create_date_key(df):
        if not df.empty and 'SENT_DATE' in df.columns:
            # Extract just the date string to prevent cross-day mismatch issues; fill NaT with 'UnknownDate'
            date_str = pd.to_datetime(df['SENT_DATE'], errors='coerce').dt.date.fillna('UnknownDate').astype(str)
            return date_str + _SEP + df['application_file'].astype(str)
        elif not df.empty:
            return "UnknownDate" + _SEP + df['application_file'].astype(str)
        return pd.Series(dtype=str)

    # Generate composite keys for all dataframes
    source_df['file_date_key'] = create_date_key(source_df)
    if inter_df is not None and not inter_df.empty:
        inter_df['file_date_key'] = create_date_key(inter_df)
    if not target_df.empty:
        target_df['file_date_key'] = create_date_key(target_df)

    # Count duplicates based on Date + Filename combination
    source_counts = source_df['file_date_key'].value_counts()
    same_name_files = source_counts[source_counts > 1]

    metrics['total_same_name_files'] = len(same_name_files)
    metrics['total_records_with_same_name'] = same_name_files.sum()
    # --------------------------------------------------

    # Core Tracking logic (Still matched on application_file to allow safe cross-day transfers)
    if inter_df is not None and not inter_df.empty:
        source_to_inter_mask = source_df['application_file'].isin(inter_df['application_file'])
    else:
        source_to_inter_mask = source_df['application_file'].isin(target_df['application_file'])

    df_source_processed = source_df[source_to_inter_mask]
    df_source_pending = source_df[~source_to_inter_mask]
    df_source_excluded = df_exclude

    dataframes['source_table'] = {
        'processed': df_source_processed,
        'pending': df_source_pending,
        'excluded': df_source_excluded
    }

    metrics['transferred_to_inter_count'] = len(df_source_processed)
    metrics['transferred_to_inter_percent'] = (len(df_source_processed) / eligible_source) * 100 if eligible_source > 0 else 0
    metrics['pending_at_source_count'] = len(df_source_pending)
    metrics['pending_at_source_percent'] = (len(df_source_pending) / eligible_source) * 100 if eligible_source > 0 else 0
    metrics['Excluded_file'] = len(df_source_excluded)

    if inter_df is not None and not inter_df.empty:
        inter_base = inter_df[inter_df['application_file'].isin(df_source_processed['application_file'])]

        inter_to_target_mask = inter_base['application_file'].isin(
            target_df['application_file']) if not target_df.empty else pd.Series([False] * len(inter_base))
        df_inter_processed = inter_base[inter_to_target_mask]
        df_inter_pending = inter_base[~inter_to_target_mask]
        df_inter_excluded = pd.DataFrame(columns=inter_df.columns)

        dataframes['intermediate_table'] = {
            'processed': df_inter_processed,
            'pending': df_inter_pending,
            'excluded': df_inter_excluded
        }

        inter_base_len = len(inter_base)
        metrics['transferred_to_target_count'] = len(df_inter_processed)
        metrics['transferred_to_target_percent'] = (
                                                           len(df_inter_processed) / inter_base_len) * 100 if inter_base_len > 0 else 0
        metrics['pending_at_inter_count'] = len(df_inter_pending)
        metrics['pending_at_inter_percent'] = (
                                                      len(df_inter_pending) / inter_base_len) * 100 if inter_base_len > 0 else 0
    else:
        df_inter_base = df_source_processed

        inter_to_target_mask = df_inter_base['application_file'].isin(
            target_df['application_file']) if not target_df.empty else pd.Series([False] * len(df_inter_base))
        df_target_processed = target_df[target_df['application_file'].isin(
            df_inter_base['application_file'])] if not target_df.empty else pd.DataFrame(columns=target_df.columns)

        base_len = len(df_inter_base)
        metrics['transferred_to_target_count'] = len(df_target_processed)
        metrics['transferred_to_target_percent'] = (len(df_target_processed) / base_len) * 100 if base_len > 0 else 0

        metrics['pending_at_inter_count'] = None
        metrics['pending_at_inter_percent'] = None

        dataframes['intermediate_table'] = {
            'processed': pd.DataFrame(columns=source_df.columns),
            'pending': pd.DataFrame(columns=source_df.columns),
            'excluded': pd.DataFrame(columns=source_df.columns)
        }

    if inter_df is not None and not inter_df.empty:
        base_target_files = dataframes['intermediate_table']['processed']['application_file']
    else:
        base_target_files = df_source_processed['application_file']

    if target_df.empty:
        df_target_filtered = pd.DataFrame(columns=target_df.columns)
    else:
        df_target_filtered = target_df[target_df['application_file'].isin(base_target_files)]

    dataframes['target_table'] = {
        'processed': df_target_filtered
    }

    # --- DUPLICATE FILE PROCESSING LOOP ---
    # duplicateFileName_DB  : files that appear more than once on the same date in the source DB.
    # MissingDuplicatefiles : a subset of the above where the SFTP layer forwarded fewer copies
    #                         than the DB recorded (overwrite / silent drop on the wire).
    # Pre-compute downstream key counts ONCE instead of re-running value_counts()
    # for every duplicate group inside the loop.
    inter_key_counts = inter_df['file_date_key'].value_counts() if (inter_df is not None and not inter_df.empty) else None
    target_key_counts = target_df['file_date_key'].value_counts() if not target_df.empty else None

    same_name_list = []
    for file_date_key in same_name_files.index:
        # Split on the unambiguous "|||" separator introduced in create_date_key.
        # Filenames may contain underscores, so the old "_" separator was unsafe.
        try:
            date_part, file_name = file_date_key.split(_SEP, 1)
        except ValueError:
            date_part, file_name = "UnknownDate", file_date_key

        source_count = int(same_name_files[file_date_key])

        # --- duplicateFileName_DB count (how many the DB saw) ---
        # Already captured by source_count above.

        # --- Check how many copies the SFTP actually forwarded ---
        # inter_count / target_count tell us what arrived downstream.
        inter_count = int(inter_key_counts.get(file_date_key, 0)) if inter_key_counts is not None else 0
        target_count = int(target_key_counts.get(file_date_key, 0)) if target_key_counts is not None else 0

        # MissingDuplicatefiles flag:
        # SFTP transmitted fewer copies than the DB recorded, meaning at least one
        # duplicate was silently overwritten or dropped in transit.
        downstream_count = inter_count if (inter_df is not None and not inter_df.empty) else target_count
        sftp_dropped_copies = max(0, source_count - downstream_count)
        missing_in_transit = sftp_dropped_copies > 0

        same_name_list.append({
            'date': date_part,
            'file_name': file_name,
            'source_count': source_count,  # duplicateFileName_DB: copies in source DB
            'inter_count': inter_count,
            'target_count': target_count,
            'sftp_dropped_copies': sftp_dropped_copies,  # MissingDuplicatefiles: copies lost on wire
            'missing_in_transit': missing_in_transit  # True when SFTP silently dropped ≥1 copy
        })

    same_name_df = pd.DataFrame(same_name_list)
    dataframes['same_name_transfers'] = same_name_df

    # ── Expose both headline metrics to the dashboard ──────────────────────────
    # duplicateFileName_DB  → total_same_name_files (already set above)
    # MissingDuplicatefiles → count of duplicate groups where SFTP dropped ≥1 copy
    metrics['missing_duplicate_files'] = (
        int(same_name_df['missing_in_transit'].sum()) if not same_name_df.empty else 0
    )
    metrics['total_sftp_dropped_copies'] = (
        int(same_name_df['sftp_dropped_copies'].sum()) if not same_name_df.empty else 0
    )
    # ───────────────────────────────────────────────────────────────────────────

    # Cleanup temporary keys before returning dataframes
    for name, df_dict in dataframes.items():
        if name != 'same_name_transfers':
            for key, df in df_dict.items():
                if 'file_date_key' in df.columns:
                    df.drop(columns=['file_date_key'], inplace=True)

    # Generate the grouped bar chart for processed records
    processed_data = {
        'source': dataframes['source_table']['processed'],
        'intermediate': dataframes['intermediate_table']['processed'],
        'target': dataframes['target_table']['processed']
    }

    bar_plot = generate_processed_records_grouped_bar(processed_data)
    if bar_plot:
        plots['processed_records_grouped_bar'] = bar_plot

    return metrics, dataframes, plots


def get_file_flow_data(report, s_date_format, start_date, end_date, i_date_format, t_date_format):
    """Get file flow data for a report with date format handling"""
    try:
        # Get data from each system with the respective date format
        source_data = get_system_data(report, 'source', s_date_format, start_date, end_date)

        # source_data=None
        intermediate_data = None
        if report.has_intermediate:
            intermediate_data = get_system_data(report, 'intermediate', i_date_format, start_date, end_date)
        target_data = get_system_data(report, 'target', t_date_format, start_date, end_date)
        # target_data=None
        # Calculate metrics — pass both exclusion sets
        exclude_data = getattr(report, 'exclude_data', None)
        exclude_data1 = getattr(report, 'exclude_data1', None)
        analysis_results = analyze_file_transfers(
            source_data, target_data, intermediate_data, exclude_data, exclude_data1
        )

        return analysis_results

    except Exception as e:
        logging.error(f"Error getting file flow data: {str(e)}")
        raise


def _empty_file_df():
    """Empty frame carrying the canonical columns the analysis expects."""
    return pd.DataFrame(columns=['application_file', 'SENT_DATE'])


def _shift_date(date_str, days):
    """Add *days* to a 'YYYY-MM-DD' string, returning the same format. Tolerant of bad input."""
    try:
        return (datetime.strptime(date_str, '%Y-%m-%d') + timedelta(days=days)).strftime('%Y-%m-%d')
    except (TypeError, ValueError):
        return date_str


def get_system_data(report, system_prefix, date_format, start_date, end_date):
    """Get data from a specific system (source, intermediate, or target) considering the date format"""
    system_type = getattr(report, f'{system_prefix}_system_type')
    if system_type is None:
        return _empty_file_df()

    # Files created late on the final day (e.g. 23:00) are routinely processed by a
    # DOWNSTREAM system on the *next* calendar day. So when reading an intermediate
    # or destination system we extend the window by one day. The source window is
    # left exactly as the user selected. Matching is by filename, so a wider
    # downstream window can only recover late arrivals — it never inflates the
    # source total.
    eff_end_date = end_date
    if system_prefix in ('intermediate', 'target'):
        eff_end_date = _shift_date(end_date, 1)

    # Compare on the enum *value* (lowercase). The previous check tested .name
    # ('ORACLE'/'MSSQL'/'LOG') against a lowercase 'mssql', so MSSQL systems
    # never matched and silently returned no data.
    if system_type.value in ('oracle', 'mssql'):
        return get_database_data(report, system_prefix, date_format, start_date, eff_end_date)
    elif system_type.value == 'log':
        return get_log_data(report, system_prefix, date_format, start_date, eff_end_date)
    else:
        return _empty_file_df()


def get_database_data(report, system_prefix, date_format, start_date, end_date):
    """Get data from a database system with date format applied"""
    try:

        system_type = getattr(report, f'{system_prefix}_system_type')
        connection_string = decrypt_password(getattr(report, f'{system_prefix}_connection_string'))
        username = getattr(report, f'{system_prefix}_username')
        password = decrypt_password(getattr(report, f'{system_prefix}_password'))
        sql_query = getattr(report, f'{system_prefix}_sql_query')
        filename_column = getattr(report, f'{system_prefix}_filename_column')
        filename_column = filename_column.upper() if filename_column else filename_column

        # Replace date placeholders in query using the provided date format
        start_date_formatted = datetime.strptime(start_date, '%Y-%m-%d').strftime(date_format)
        end_date_formatted = datetime.strptime(end_date, '%Y-%m-%d').strftime(date_format)

        query = sql_query.replace('{start_date}', start_date_formatted)
        query = query.replace('{end_date}', end_date_formatted)

        # Open, query, and ALWAYS release the connection — even if the query raises.
        # A read-only fetch with a hard timeout so a slow/locked query can never
        # hold a session open against the production database.
        conn = None
        try:
            if system_type.value == 'oracle':
                cx_Oracle = _import_cx_oracle()
                conn = cx_Oracle.connect(username, password, connection_string)
                try:
                    conn.call_timeout = 60000  # ms — abort runaway queries
                except Exception:
                    pass
            else:  # mssql
                pyodbc = _import_pyodbc()
                conn = pyodbc.connect(connection_string, timeout=15)  # login timeout (s)
                try:
                    conn.timeout = 60  # query timeout (s)
                except Exception:
                    pass

            df = pd.read_sql(query, conn)
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass

        # Apply exclusions if configured
        # excluded_column = getattr(report, f'{system_prefix}_excluded_column')

        # excluded_values_json = getattr(report, f'{system_prefix}_excluded_values')

        # if excluded_column and excluded_values_json and excluded_column in df.columns:
        #    try:
        #        excluded_column=excluded_column.upper()
        #        excluded_values = json.loads(excluded_values_json)
        #        df = df[~df[excluded_column].isin(excluded_values)]
        #    except:
        #        pass  # Continue without exclusions if JSON parsing fails

        if filename_column and filename_column in df.columns:
            df = df.rename(columns={filename_column: 'application_file'})
        if 'application_file' not in df.columns:
            df['application_file'] = pd.Series(dtype=str)

        # Rename stat columns if available
        primary_stat_pattern = getattr(report, f'{system_prefix}_primary_stats_column', None)
        if primary_stat_pattern:
            primary_stat_pattern = primary_stat_pattern.upper()
        secondary_stat_pattern = getattr(report, f'{system_prefix}_secondary_stats_column', None)
        if secondary_stat_pattern:
            secondary_stat_pattern = secondary_stat_pattern.upper()

        if primary_stat_pattern:
            df = df.rename(columns={primary_stat_pattern: 'primary_stat'})
        if secondary_stat_pattern:
            df = df.rename(columns={secondary_stat_pattern: 'secondary_stat'})

        return df

    except Exception as e:
        logging.error(f"Error getting database data: {str(e)}")
        # Return an empty frame (not None) so the analysis degrades gracefully
        # instead of crashing on len()/.empty downstream.
        return _empty_file_df()


##def extract_data_from_content(line, pattern):
#   """
#   Extract data from a log file line based on the provided pattern.

#    Args:
#        line (str): The line of text to search through.
#        pattern (str): The regular expression pattern to use for extraction.
#
#    Returns:
#        str: The extracted data, or None if no match was found.
#    """
#    regex_pattern=re.escape(pattern).replace(r'\{data\}',r'([^/]+)')
#    match = re.search(regex_pattern, line)
#    #logging.error(f"pattern : {pattern}")
#    #logging.error(f"regex : {regex_pattern}")
#    #logging.error(f"line : {line}")
#    if match:
#        return match.group(1)  # Return the matched string (or adjust this based on how you want to extract it)
#    return None


def get_log_data(report, system_prefix, date_format, start_date, end_date):
    """Get data from log files via SFTP, applying date format for file extraction and dynamic extraction logic."""
    try:
        # Get configuration attributes from the report object
        hostname = getattr(report, f'{system_prefix}_hostname', None)
        path = getattr(report, f'{system_prefix}_path', None)
        username = getattr(report, f'{system_prefix}_sftp_username', None)
        password = decrypt_password(getattr(report, f'{system_prefix}_sftp_password', None))
        file_naming_convention = getattr(report, f'{system_prefix}_file_naming_convention', None)
        file_extract_pattern = getattr(report, f'{system_prefix}_extraction_pattern', None)
        split_pattern = getattr(report, f'{system_prefix}_data_split', None)
        # The stats position is stored on the *_stats_pattern column (the form's
        # "Stats Extraction Pattern"); the old code read a non-existent
        # *_primary_stat_pattern attr, so the stat field was never captured.
        primary_stat_position = getattr(report, f'{system_prefix}_stats_pattern', None)
        filename_position = getattr(report, f'{system_prefix}_data_fileName', None)

        # Convert positions to integers if provided
        filename_position = int(filename_position) if filename_position is not None else None
        primary_stat_position = int(primary_stat_position) if primary_stat_position is not None else None

        # Validate required configurations
        if not all([hostname, path, username, password, file_naming_convention, file_extract_pattern, split_pattern]):
            logging.error("Missing required configuration for log extraction.")
            return None

        # Connect to SFTP. The whole session is wrapped in try/finally so the SSH
        # and SFTP channels are ALWAYS released — even if a read fails mid-way —
        # and never left open against the production server.
        paramiko = _import_paramiko()
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        sftp = None
        filenames, stat_columns, file_dates = [], [], []
        try:
            ssh.connect(hostname, username=username, password=password, timeout=10)
            sftp = ssh.open_sftp()
            files = sftp.listdir(path)

            # The downstream end_date+1 is applied upstream in get_system_data, so the
            # window here is used verbatim (inclusive of end_date).
            current_date = datetime.strptime(start_date, '%Y-%m-%d')
            end_date_obj = datetime.strptime(end_date, '%Y-%m-%d')

            # Process each day's logs
            while current_date <= end_date_obj:
                date_str = current_date.strftime(date_format)
                expected_filename_part = file_naming_convention.replace('{date}', date_str)

                for file in files:
                    if expected_filename_part in file:
                        try:
                            # Stream line-by-line rather than read().decode() the whole
                            # file into memory — keeps memory flat on large prod logs.
                            with sftp.open(f"{path}/{file}", "r") as f:
                                f.prefetch()
                                for raw in f:
                                    line = raw.decode('utf-8', 'replace') if isinstance(raw, (bytes, bytearray)) else raw
                                    if file_extract_pattern in line:
                                        record_split = line.strip().split(split_pattern)

                                        # Validate filename position
                                        if filename_position is not None and len(record_split) > filename_position:
                                            transfer_file = record_split[filename_position].strip()
                                        else:
                                            continue  # skip malformed line

                                        # Optionally extract stat/flow field
                                        if primary_stat_position is not None and len(record_split) > primary_stat_position:
                                            stat_field = record_split[primary_stat_position].strip()
                                        else:
                                            stat_field = None

                                        filenames.append(transfer_file)
                                        stat_columns.append(stat_field)
                                        file_dates.append(current_date)
                        except Exception as e:
                            logging.error(f"Error processing file {file}: {str(e)}")
                            continue
                current_date += pd.Timedelta(days=1)
        finally:
            if sftp is not None:
                try:
                    sftp.close()
                except Exception:
                    pass
            try:
                ssh.close()
            except Exception:
                pass

        # Return DataFrame
        if not filenames:
            logging.warning("No matching data found in logs.")
            base_cols = ['application_file', 'SENT_DATE']
            if primary_stat_position is not None:
                base_cols.append('flow_type')
            return pd.DataFrame(columns=base_cols)

        # Build result
        result = {
            'application_file': filenames,
            'SENT_DATE': file_dates
        }
        if primary_stat_position is not None:
            result['flow_type'] = stat_columns

        return pd.DataFrame(result)

    except Exception as e:
        logging.error(f"Error getting log data: {str(e)}")
        return _empty_file_df()