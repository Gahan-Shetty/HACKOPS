import React from 'react';

function AIPanel() {
  return (
    <div className="bg-gray-900 rounded-xl p-4 border border-gray-700">
      <h2 className="text-white font-bold text-lg mb-4">🤖 AI Threat Summary</h2>
      <div className="bg-gray-800 rounded-lg p-4 border border-green-700">
        <p className="text-green-400 text-sm leading-relaxed">
          "The APK attempted background persistence and communicated with a suspicious
          foreign IP address. DNS abuse detected, indicating possible C2 communication.
          Hidden file creation suggests payload deployment behavior consistent with
          <span className="text-red-400 font-bold"> Spyware / Remote Access Trojan</span>."
        </p>
      </div>
      <div className="mt-4">
        <p className="text-gray-400 text-xs font-semibold uppercase mb-2">Recommended Actions</p>
        <ul className="text-gray-300 text-sm space-y-1">
          <li>✅ Isolate device from network immediately</li>
          <li>✅ Revoke SMS and storage permissions</li>
          <li>✅ Blacklist detected IP addresses</li>
          <li>✅ Quarantine dropped payload files</li>
        </ul>
      </div>
    </div>
  );
}

export default AIPanel;