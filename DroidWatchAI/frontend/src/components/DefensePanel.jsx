import React, { useState } from 'react';

function DefensePanel() {
  const [log, setLog] = useState([]);

  const actions = [
    { label: '🔥 Block IP', message: 'Malicious IP 192.168.1.105 blocked by firewall' },
    { label: '🗂️ Quarantine File', message: 'Suspicious file /data/payload.apk quarantined' },
    { label: '⚙️ Kill Process', message: 'Hidden background process PID 2043 terminated' },
    { label: '🔒 Revoke Permissions', message: 'SMS and Storage permissions revoked' },
  ];

  const handleAction = (message) => {
    const time = new Date().toLocaleTimeString();
    setLog((prev) => [`[${time}] ${message}`, ...prev]);
  };

  return (
    <div className="bg-gray-900 rounded-xl p-4 border border-gray-700">
      <h2 className="text-white font-bold text-lg mb-4">🛡️ Defense Simulation</h2>
      <div className="grid grid-cols-2 gap-2 mb-4">
        {actions.map((a) => (
          <button
            key={a.label}
            onClick={() => handleAction(a.message)}
            className="bg-blue-700 hover:bg-blue-600 text-white text-sm font-semibold py-2 px-3 rounded-lg transition"
          >
            {a.label}
          </button>
        ))}
      </div>
      <div className="bg-gray-800 rounded-lg p-3 h-32 overflow-y-auto">
        {log.length === 0 ? (
          <p className="text-gray-500 text-xs">No defense actions yet...</p>
        ) : (
          log.map((entry, i) => (
            <p key={i} className="text-green-400 text-xs mb-1">{entry}</p>
          ))
        )}
      </div>
    </div>
  );
}

export default DefensePanel;