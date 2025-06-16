import { useState, useEffect } from 'react';
import axios from 'axios';
import './App.css';

const API_BASE_URL = import.meta.env.VITE_API_URL || "http://192.168.107.192:8000"; // Fallback for development

function Navbar({ currentView, setView }) {
  const navStyle = { display: 'flex', justifyContent: 'space-around', padding: '10px', background: '#222', color: '#fff' };
  const buttonStyle = (view) => ({
    backgroundColor: currentView === view ? '#555' : '#333',
    border: 'none', padding: '10px 15px', borderRadius: '5px', cursor: 'pointer', color: 'white'
  });

  return (
    <nav style={navStyle}>
      {["dashboard", "logs", "start", "stop", "info"].map((view) => (
        <button key={view} style={buttonStyle(view)} onClick={() => setView(view)}>
          {view.charAt(0).toUpperCase() + view.slice(1)}
        </button>
      ))}
    </nav>
  );
}

function LiveLogs() {
  const [logs, setLogs] = useState([]);

  useEffect(() => {
    const fetchLogs = async () => {
      try {
        const response = await axios.get(`${API_BASE_URL}/alerts/latest`);
        const rawLogs = response.data.alerts || [];
        const formatted = rawLogs.map(a =>
          `[${a.timestamp}] ${a.severity.toUpperCase()} - ${a.details?.process_name} (confidence: ${(a.confidence * 100).toFixed(1)}%)`
        );
        setLogs(formatted);
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
          <p key={idx} style={{ color: '#0f0', margin: 0 }}>{log}</p>
        )) : <p style={{ color: 'gray' }}>No alerts yet.</p>}
      </div>
    </div>
  );
}

function Dashboard() {
  const [stats, setStats] = useState(null);

  useEffect(() => {
    const fetchStats = async () => {
      try {
        const response = await axios.get(`${API_BASE_URL}/stats`);
        setStats(response.data);
      } catch (error) {
        console.error('Error fetching stats:', error);
      }
    };

    fetchStats();
    const interval = setInterval(fetchStats, 10000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div style={{ padding: '20px' }}>
      <h2>System Status</h2>
      {stats ? (
        <>
          <p><strong>Running:</strong> {stats.total_syscalls > 0 ? '✅' : '⏹️'}</p>
          <p><strong>Syscalls Parsed:</strong> {stats.total_syscalls}</p>
          <p><strong>Alerts Generated:</strong> {stats.alerts_generated}</p>
          <p><strong>Lines Processed:</strong> {stats.lines_processed}</p>
          <p><strong>Detection Rate:</strong> {(stats.detection_rate * 100).toFixed(1)}%</p>
          <p><strong>Uptime:</strong> {stats.uptime}</p>
        </>
      ) : (
        <p>Loading stats...</p>
      )}
    </div>
  );
}

function ControlPanel({ action }) {
  const handleAction = async () => {
    try {
      const response = await axios.post(`${API_BASE_URL}/control/${action}`);
      alert(response.data.message || `${action} command sent.`);
    } catch (error) {
      alert(`Error: ${error.response?.data?.detail || error.message}`);
    }
  };

  return (
    <div style={{ padding: '20px' }}>
      <h2>{action === 'start' ? 'Start' : 'Stop'} Monitoring</h2>
      <button
        onClick={handleAction}
        style={{
          padding: '10px 20px',
          backgroundColor: action === 'start' ? 'green' : 'red',
          color: 'white', border: 'none', borderRadius: '5px', cursor: 'pointer'
        }}
      >
        {action === 'start' ? '▶️ Start' : '⏹️ Stop'}
      </button>
    </div>
  );
}

function SystemInfo() {
  const [info, setInfo] = useState(null);

  useEffect(() => {
    const fetchInfo = async () => {
      try {
        const response = await axios.get(`${API_BASE_URL}/model/info`);
        setInfo(response.data);
      } catch (error) {
        console.error('Error fetching system info:', error);
      }
    };
    fetchInfo();
  }, []);

  return (
    <div style={{ padding: '20px' }}>
      <h2>Model Info</h2>
      {info ? (
        <pre style={{ background: '#111', padding: '10px', color: 'lightblue' }}>
          {JSON.stringify(info, null, 2)}
        </pre>
      ) : (
        <p>Loading model info...</p>
      )}
    </div>
  );
}

function App() {
  const [currentView, setView] = useState('dashboard');

  return (
    <div>
      <header style={{ color: 'white', padding: '20px', textAlign: 'center', background: '#000' }}>
        <h1>🛡️ AI-Powered IDS</h1>
        <p>Real-time syscall anomaly detection</p>
      </header>
      <Navbar currentView={currentView} setView={setView} />
      <main style={{ background: '#000', minHeight: '100vh', color: 'white' }}>
        {{
          dashboard: <Dashboard />,
          logs: <LiveLogs />,
          start: <ControlPanel action="start" />,
          stop: <ControlPanel action="stop" />,
          info: <SystemInfo />
        }[currentView] || <Dashboard />}
      </main>
    </div>
  );
}

export default App;
