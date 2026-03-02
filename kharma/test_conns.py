import psutil
try:
    conns = psutil.net_connections(kind='inet')
    print(f"Total connections fetched: {len(conns)}")
    important_states = ('ESTABLISHED', 'LISTEN', 'CLOSE_WAIT', 'FIN_WAIT1', 'FIN_WAIT2')
    filtered = [c for c in conns if c.status in important_states and c.laddr]
    print(f"Filtered (valuable) connections: {len(filtered)}")
    if filtered:
        print("Sample:", filtered[0])
except Exception as e:
    print(f"Error: {e}")
