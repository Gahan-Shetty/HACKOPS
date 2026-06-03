import React from 'react';
import { Line } from 'react-chartjs-2';
import { Chart as ChartJS, CategoryScale, LinearScale, PointElement, LineElement, Tooltip, Legend } from 'chart.js';

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, Tooltip, Legend);

const data = {
  labels: ['00:01', '00:02', '00:03', '00:04', '00:05', '00:06', '00:07'],
  datasets: [{
    label: 'Attack Events',
    data: [2, 5, 3, 8, 12, 7, 15],
    borderColor: '#22c55e',
    backgroundColor: 'rgba(34,197,94,0.1)',
    tension: 0.4,
    fill: true,
  }],
};

const options = {
  plugins: { legend: { labels: { color: '#9ca3af' } } },
  scales: {
    x: { ticks: { color: '#9ca3af' }, grid: { color: '#374151' } },
    y: { ticks: { color: '#9ca3af' }, grid: { color: '#374151' } },
  },
};

function AttackTimeline() {
  return (
    <div className="bg-gray-900 rounded-xl p-4 border border-gray-700">
      <h2 className="text-white font-bold text-lg mb-4">📈 Attack Timeline</h2>
      <Line data={data} options={options} />
    </div>
  );
}

export default AttackTimeline;