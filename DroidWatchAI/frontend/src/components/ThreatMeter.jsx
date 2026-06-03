import React from 'react';
import { Doughnut } from 'react-chartjs-2';
import { Chart as ChartJS, ArcElement, Tooltip, Legend } from 'chart.js';

ChartJS.register(ArcElement, Tooltip, Legend);

function ThreatMeter() {
  const level = 78;

  const data = {
    datasets: [{
      data: [level, 100 - level],
      backgroundColor: ['#ef4444', '#1f2937'],
      borderWidth: 0,
    }],
  };

  return (
    <div className="bg-gray-900 rounded-xl p-4 border border-gray-700 flex flex-col items-center">
      <h2 className="text-white font-bold text-lg mb-4 self-start">🌡️ Threat Severity</h2>
      <div className="w-48 h-48 relative">
        <Doughnut data={data} options={{ cutout: '75%', plugins: { legend: { display: false } } }} />
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-red-400 text-3xl font-bold">{level}%</span>
          <span className="text-red-300 text-sm font-semibold">HIGH</span>
        </div>
      </div>
      <div className="flex gap-4 mt-4 text-xs">
        <span className="text-green-400">● LOW</span>
        <span className="text-yellow-400">● MEDIUM</span>
        <span className="text-red-400">● HIGH</span>
      </div>
    </div>
  );
}

export default ThreatMeter;