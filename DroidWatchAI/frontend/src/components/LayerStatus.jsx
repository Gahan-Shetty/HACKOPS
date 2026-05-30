import React from 'react';

const layers = [
  { name: 'Network Layer', status: 'UNDER ATTACK', attacks: ['C2 Callback Detected', 'DNS Abuse', 'Suspicious IP'], color: 'red' },
  { name: 'File System Layer', status: 'UNDER ATTACK', attacks: ['Hidden File Created', 'Payload Dropped'], color: 'orange' },
  { name: 'System Layer', status: 'SAFE', attacks: [], color: 'green' },
];

function LayerStatus() {
  return (
    <div className="bg-gray-900 rounded-xl p-4 border border-gray-700">
      <h2 className="text-white font-bold text-lg mb-4">⚔️ Attack Layer Map</h2>
      <div className="flex flex-col gap-3">
        {layers.map((layer) => (
          <div key={layer.name} className={`rounded-lg p-3 border ${
            layer.color === 'red' ? 'border-red-500 bg-red-950' :
            layer.color === 'orange' ? 'border-orange-500 bg-orange-950' :
            'border-green-500 bg-green-950'
          }`}>
            <div className="flex justify-between items-center">
              <span className="text-white font-semibold">{layer.name}</span>
              <span className={`text-xs font-bold px-2 py-1 rounded ${
                layer.color === 'red' ? 'bg-red-500 text-white' :
                layer.color === 'orange' ? 'bg-orange-500 text-white' :
                'bg-green-500 text-black'
              }`}>{layer.status}</span>
            </div>
            {layer.attacks.length > 0 && (
              <ul className="mt-2">
                {layer.attacks.map((a) => (
                  <li key={a} className="text-gray-300 text-xs mt-1">• {a}</li>
                ))}
              </ul>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

export default LayerStatus;