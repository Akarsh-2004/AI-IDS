#!/usr/bin/env python3
"""
Syscall Monitor GUI - Standalone Executable
Simple Tkinter interface for real-time IDS monitoring
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import time
import joblib
import random
from collections import deque
from datetime import datetime
import queue

class SyscallMonitorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Syscall Monitor - Real-time IDS")
        self.root.geometry("1000x700")
        self.root.configure(bg='#2c3e50')
        
        # Initialize variables
        self.monitoring = False
        self.model = None
        self.vectorizer = None
        self.syscall_history = deque(maxlen=10)
        self.consecutive_malicious = 0
        self.MALICIOUS_THRESHOLD = 1
        self.alert_queue = queue.Queue()
        self.stats = {
            'total_syscalls': 0,
            'malicious_count': 0,
            'alerts_triggered': 0,
            'start_time': None
        }
        
        self.setup_ui()
        self.load_model()
        
        # Start GUI update loop
        self.root.after(100, self.update_gui)
    
    def setup_ui(self):
        """Setup the main UI components"""
        # Create main frames
        self.create_header()
        self.create_control_panel()
        self.create_status_panel()
        self.create_activity_panel()
        self.create_alerts_panel()
        self.create_stats_panel()
    
    def create_header(self):
        """Create header with title and status"""
        header_frame = tk.Frame(self.root, bg='#34495e', height=60)
        header_frame.pack(fill=tk.X, padx=10, pady=5)
        header_frame.pack_propagate(False)
        
        title_label = tk.Label(header_frame, text="🛡️ Syscall Monitor - Real-time IDS", 
                              font=("Arial", 16, "bold"), fg='white', bg='#34495e')
        title_label.pack(side=tk.LEFT, padx=20, pady=15)
        
        self.status_label = tk.Label(header_frame, text="● STOPPED", 
                                   font=("Arial", 12, "bold"), fg='#e74c3c', bg='#34495e')
        self.status_label.pack(side=tk.RIGHT, padx=20, pady=15)
    
    def create_control_panel(self):
        """Create control buttons"""
        control_frame = tk.Frame(self.root, bg='#2c3e50')
        control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.start_btn = tk.Button(control_frame, text="▶️ Start Monitoring", 
                                  command=self.start_monitoring, bg='#27ae60', fg='white',
                                  font=("Arial", 10, "bold"), width=15)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = tk.Button(control_frame, text="⏹️ Stop Monitoring", 
                                 command=self.stop_monitoring, bg='#e74c3c', fg='white',
                                 font=("Arial", 10, "bold"), width=15, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        self.clear_btn = tk.Button(control_frame, text="🗑️ Clear Logs", 
                                  command=self.clear_logs, bg='#f39c12', fg='white',
                                  font=("Arial", 10, "bold"), width=15)
        self.clear_btn.pack(side=tk.LEFT, padx=5)
        
        # Threshold setting
        tk.Label(control_frame, text="Alert Threshold:", bg='#2c3e50', fg='white').pack(side=tk.LEFT, padx=(20,5))
        self.threshold_var = tk.StringVar(value="1")
        threshold_spin = tk.Spinbox(control_frame, from_=1, to=10, width=5, textvariable=self.threshold_var)
        threshold_spin.pack(side=tk.LEFT, padx=5)
    
    def create_status_panel(self):
        """Create status information panel"""
        status_frame = tk.LabelFrame(self.root, text="System Status", bg='#34495e', fg='white', 
                                   font=("Arial", 10, "bold"))
        status_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Status labels
        info_frame = tk.Frame(status_frame, bg='#34495e')
        info_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.model_status = tk.Label(info_frame, text="Model: Not Loaded", bg='#34495e', fg='#e74c3c')
        self.model_status.pack(side=tk.LEFT)
        
        self.runtime_label = tk.Label(info_frame, text="Runtime: 00:00:00", bg='#34495e', fg='white')
        self.runtime_label.pack(side=tk.RIGHT)
    
    def create_activity_panel(self):
        """Create real-time activity log"""
        activity_frame = tk.LabelFrame(self.root, text="Real-time Activity", bg='#34495e', fg='white',
                                     font=("Arial", 10, "bold"))
        activity_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.activity_text = scrolledtext.ScrolledText(activity_frame, height=10, bg='#2c3e50', fg='#ecf0f1',
                                                      font=("Consolas", 9), wrap=tk.WORD)
        self.activity_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def create_alerts_panel(self):
        """Create alerts panel"""
        alerts_frame = tk.LabelFrame(self.root, text="🚨 Security Alerts", bg='#34495e', fg='white',
                                   font=("Arial", 10, "bold"))
        alerts_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.alerts_text = scrolledtext.ScrolledText(alerts_frame, height=8, bg='#1a1a1a', fg='#ff6b6b',
                                                    font=("Consolas", 9, "bold"), wrap=tk.WORD)
        self.alerts_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def create_stats_panel(self):
        """Create statistics panel"""
        stats_frame = tk.LabelFrame(self.root, text="Statistics", bg='#34495e', fg='white',
                                  font=("Arial", 10, "bold"))
        stats_frame.pack(fill=tk.X, padx=10, pady=5)
        
        stats_inner = tk.Frame(stats_frame, bg='#34495e')
        stats_inner.pack(fill=tk.X, padx=10, pady=5)
        
        self.stats_labels = {}
        stats_items = [
            ("Total Syscalls", "0"),
            ("Malicious Detected", "0"),
            ("Alerts Triggered", "0"),
            ("Detection Rate", "0.0%")
        ]
        
        for i, (label, value) in enumerate(stats_items):
            frame = tk.Frame(stats_inner, bg='#34495e')
            frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
            
            tk.Label(frame, text=label, bg='#34495e', fg='#bdc3c7', font=("Arial", 8)).pack()
            stat_label = tk.Label(frame, text=value, bg='#34495e', fg='white', font=("Arial", 12, "bold"))
            stat_label.pack()
            self.stats_labels[label.lower().replace(' ', '_')] = stat_label
    
    def load_model(self):
        """Load the ML model and vectorizer"""
        try:
            self.model = joblib.load("models/model_os/rf_ids_model.joblib")
            self.vectorizer = joblib.load("models/model_os/tfidf_vectorizer.joblib")
            self.model_status.config(text="Model: ✅ Loaded", fg='#27ae60')
            self.log_activity("✅ Model and vectorizer loaded successfully")
        except Exception as e:
            self.model_status.config(text="Model: ❌ Failed", fg='#e74c3c')
            self.log_activity(f"❌ Failed to load model: {str(e)}")
            messagebox.showerror("Model Error", f"Failed to load model:\n{str(e)}")
    
    def start_monitoring(self):
        """Start the monitoring process"""
        if not self.model or not self.vectorizer:
            messagebox.showerror("Error", "Model not loaded. Please check model files.")
            return
        
        self.monitoring = True
        self.stats['start_time'] = time.time()
        self.MALICIOUS_THRESHOLD = int(self.threshold_var.get())
        
        # Update UI
        self.status_label.config(text="● MONITORING", fg='#27ae60')
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        
        # Start monitoring thread
        self.monitor_thread = threading.Thread(target=self.monitor_syscalls, daemon=True)
        self.monitor_thread.start()
        
        self.log_activity("🚀 Monitoring started")
        self.log_alert("🔥 IDS SYSTEM ACTIVATED - Monitoring for malicious activity")
    
    def stop_monitoring(self):
        """Stop the monitoring process"""
        self.monitoring = False
        
        # Update UI
        self.status_label.config(text="● STOPPED", fg='#e74c3c')
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        
        self.log_activity("⏹️ Monitoring stopped")
        self.log_alert("🛑 IDS SYSTEM DEACTIVATED")
    
    def clear_logs(self):
        """Clear all logs"""
        self.activity_text.delete(1.0, tk.END)
        self.alerts_text.delete(1.0, tk.END)
        self.log_activity("🗑️ Logs cleared")
    
    def monitor_syscalls(self):
        """Main monitoring loop - runs in separate thread"""
        while self.monitoring:
            try:
                # Simulate getting syscall (replace with actual syscall source)
                syscall = self.get_syscall()
                
                if syscall:
                    self.stats['total_syscalls'] += 1
                    self.syscall_history.append(str(syscall))
                    
                    # Prepare data for prediction
                    history_string = " ".join(self.syscall_history)
                    vector = self.vectorizer.transform([history_string])
                    prediction = self.model.predict(vector)
                    probabilities = self.model.predict_proba(vector)
                    confidence = max(probabilities[0])
                    
                    # Check for malicious activity
                    if prediction[0] == 1:
                        self.consecutive_malicious += 1
                        self.stats['malicious_count'] += 1
                        
                        # Queue activity log
                        self.alert_queue.put(('activity', f"⚠️  Syscall {syscall} - MALICIOUS (confidence: {confidence:.2f})"))
                        
                        # Trigger alert if threshold reached
                        if self.consecutive_malicious >= self.MALICIOUS_THRESHOLD:
                            self.stats['alerts_triggered'] += 1
                            alert_msg = f"🚨 MALICIOUS ACTIVITY DETECTED!\n"
                            alert_msg += f"Syscalls: {list(self.syscall_history)}\n"
                            alert_msg += f"Confidence: {confidence:.2f}\n"
                            alert_msg += f"Time: {datetime.now().strftime('%H:%M:%S')}\n"
                            alert_msg += "-" * 50
                            
                            self.alert_queue.put(('alert', alert_msg))
                            self.consecutive_malicious = 0
                            time.sleep(2)  # Pause after alert
                    else:
                        self.consecutive_malicious = 0
                        self.alert_queue.put(('activity', f"✅ Syscall {syscall} - Normal (confidence: {confidence:.2f})"))
                
                time.sleep(0.1)  # Control monitoring speed
                
            except Exception as e:
                self.alert_queue.put(('activity', f"❌ Error in monitoring: {str(e)}"))
                time.sleep(1)
    
    def get_syscall(self):
        """Simulate syscall generation (replace with actual syscall source)"""
        # Simulate realistic syscall distribution
        common_syscalls = [1, 2, 3, 4, 5, 8, 21, 43, 78, 102]  # 90% probability
        suspicious_syscalls = [59, 265, 168, 240, 91]  # 8% probability
        malicious_syscalls = [1337, 9999, 666]  # 2% probability
        
        rand = random.random()
        if rand < 0.9:
            return random.choice(common_syscalls)
        elif rand < 0.98:
            return random.choice(suspicious_syscalls)
        else:
            return random.choice(malicious_syscalls)
    
    def log_activity(self, message):
        """Log activity to the activity panel"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        self.activity_text.insert(tk.END, log_entry)
        self.activity_text.see(tk.END)
    
    def log_alert(self, message):
        """Log alert to the alerts panel"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        alert_entry = f"[{timestamp}] {message}\n"
        self.alerts_text.insert(tk.END, alert_entry)
        self.alerts_text.see(tk.END)
    
    def update_gui(self):
        """Update GUI elements - runs in main thread"""
        # Process queued messages
        try:
            while True:
                msg_type, message = self.alert_queue.get_nowait()
                if msg_type == 'activity':
                    self.log_activity(message)
                elif msg_type == 'alert':
                    self.log_alert(message)
        except queue.Empty:
            pass
        
        # Update statistics
        if self.stats['start_time']:
            runtime = time.time() - self.stats['start_time']
            hours, remainder = divmod(int(runtime), 3600)
            minutes, seconds = divmod(remainder, 60)
            self.runtime_label.config(text=f"Runtime: {hours:02d}:{minutes:02d}:{seconds:02d}")
            
            # Update stats labels
            self.stats_labels['total_syscalls'].config(text=str(self.stats['total_syscalls']))
            self.stats_labels['malicious_detected'].config(text=str(self.stats['malicious_count']))
            self.stats_labels['alerts_triggered'].config(text=str(self.stats['alerts_triggered']))
            
            # Calculate detection rate
            if self.stats['total_syscalls'] > 0:
                detection_rate = (self.stats['malicious_count'] / self.stats['total_syscalls']) * 100
                self.stats_labels['detection_rate'].config(text=f"{detection_rate:.1f}%")
        
        # Schedule next update
        self.root.after(100, self.update_gui)

def main():
    """Main application entry point"""
    root = tk.Tk()
    
    # Set application icon and style
    try:
        root.iconbitmap('icon.ico')  # Add your icon file
    except:
        pass  # Ignore if icon file doesn't exist
    
    # Create and run the application
    app = SyscallMonitorGUI(root)
    
    # Handle window close
    def on_closing():
        if app.monitoring:
            app.stop_monitoring()
        root.destroy()
    
    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()

if __name__ == "__main__":
    main()
