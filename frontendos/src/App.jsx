import { useState, useEffect } from 'react';
import axios from 'axios';
import './App.css';

const API_BASE_URL = 'http://localhost:8000';

function Navbar({ currentView, setView }) {
  const navStyle = {
    display: 'flex',
    justifyContent: 'space-around',
    alignItems: 'center',
    padding: '10px',
    color: 'white',
    fontWeight: 'bold',
    position: 'sticky',
    top: 0,
    zIndex: 1000
  };

  const buttonStyle = (view) => ({
    backgroundColor: currentView === view ? '#555' : '#333',
    border: 'none',
    padding: '10px 15px',
    borderRadius: '5px',
    cursor: 'pointer',
    color: 'white'
  });

  return (
    <nav style={navStyle}>
      <button style={buttonStyle('dashboard')} onClick={() => setView('dashboard')}>Dashboard</button>
      <button style={buttonStyle('logs')} onClick={() => setView('logs')}>Live Logs</button>
      <button style={buttonStyle('start')} onClick={() => setView('start')}>Start Monitoring</button>
      <button style={buttonStyle('stop')} onClick={() => setView('stop')}>Stop Monitoring</button>
      <button style={buttonStyle('info')} onClick={() => setView('info')}>System Info</button>
    </nav>
  );
}

function LiveLogs() {
  const [logs, setLogs] = useState([]);

  useEffect(() => {
    const fetchLogs = async () => {
      try {
        const response = await axios.get(`${API_BASE_URL}/api/logs`);
        setLogs(response.data.logs || []);
      } catch (error) {
        console.error('Error fetching logs:', error);
      }
    };

    fetchLogs();
    const interval = setInterval(fetchLogs, 5000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div style={{ padding: '20px' }}>
      <h2>Live Logs</h2>
      <div style={{ maxHeight: '300px', overflowY: 'scroll', background: '#111', padding: '10px' }}>
        {logs.length ? logs.map((log, idx) => (
          <p key={idx} style={{ color: '#0f0' }}>{log}</p>
        )) : <p>No logs found.</p>}
      </div>
    </div>
  );
}

function Dashboard() {
  const [warnings, setWarnings] = useState(0);
  const [isWarning, setIsWarning] = useState(false);
  const [linux, setLinux] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchStatus = async () => {
      try {
        const response = await axios.get(`${API_BASE_URL}/api/status`);
        setWarnings(response.data.warnings);
        setIsWarning(response.data.is_warning);
        setLinux(response.data.linux);
      } catch (error) {
        console.error('Error fetching status:', error);
      } finally {
        setLoading(false);
      }
    };
    fetchStatus();
  }, []);

  return (
    <div style={{ padding: '20px' }}>
      <h2>System Status</h2>
      {loading ? <p>Loading status...</p> : (
        <>
          {isWarning && <p style={{ color: 'orange' }}>⚠️ {warnings} warnings detected</p>}
          {linux && <p style={{ color: 'lightgreen' }}>✅ Linux system detected</p>}
        </>
      )}
    </div>
  );
}

function ControlPanel({ action }) {
  const handleAction = async () => {
    try {
      const response = await axios.post(`${API_BASE_URL}/api/${action}`);
      alert(response.data.message || `${action} action sent.`);
    } catch (error) {
      alert('Error performing action.');
      console.error(error);
    }
  };

  return (
    <div style={{ padding: '20px' }}>
      <h2>{action === 'start' ? 'Start' : 'Stop'} Monitoring</h2>
      <button onClick={handleAction} style={{
        padding: '10px 20px',
        backgroundColor: action === 'start' ? 'green' : 'red',
        color: 'white',
        border: 'none',
        borderRadius: '5px',
        cursor: 'pointer'
      }}>
        {action === 'start' ? 'Start' : 'Stop'} Monitoring
      </button>
    </div>
  );
}

function SystemInfo() {
  const [info, setInfo] = useState(null);

  useEffect(() => {
    const fetchInfo = async () => {
      try {
        const response = await axios.get(`${API_BASE_URL}/api/system`);
        setInfo(response.data);
      } catch (error) {
        console.error('Error fetching system info:', error);
      }
    };
    fetchInfo();
  }, []);

  return (
    <div style={{ padding: '20px' }}>
      <h2>System Info</h2>
      {info ? (
        <pre style={{ background: '#111', padding: '10px', color: 'lightblue' }}>{JSON.stringify(info, null, 2)}</pre>
      ) : <p>Loading system info...</p>}
    </div>
  );
}

function App() {
  const [currentView, setView] = useState('dashboard');

  const renderView = () => {
    switch (currentView) {
      case 'dashboard': return <Dashboard />;
      case 'logs': return <LiveLogs />;
      case 'start': return <ControlPanel action="start" />;
      case 'stop': return <ControlPanel action="stop" />;
      case 'info': return <SystemInfo />;
      default: return <Dashboard />;
    }
  };

  return (
    <div>
      <header style={{  color: 'white', padding: '20px', textAlign: 'center' }}>
        <h1>Real-Time Intrusion Detection System</h1>
        <p>Monitoring Linux syscalls for suspicious behavior</p>
      </header>
      <Navbar currentView={currentView} setView={setView} />
      <main style={{ background: '#000', minHeight: '100vh', color: 'white' }}>
        {renderView()}
      </main>
    </div>
  );
}

export default App;
