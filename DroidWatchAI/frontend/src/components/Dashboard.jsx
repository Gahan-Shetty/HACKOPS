import React from 'react';
import LayerStatus from './LayerStatus';
import ThreatMeter from './ThreatMeter';
import AttackTimeline from './AttackTimeline';
import C2Graph from './C2Graph';
import DefensePanel from './DefensePanel';
import AIPanel from './AIPanel';

function Dashboard() {
  return (
    <div className="p-6">

      {/* Header */}
      <div className="mb-6">
        <h1 className="text-3xl font-bold text-green-400">
          🛡️ DroidWatch AI
        </h1>
        <p className="text-gray-400 text-sm mt-1">
          Android Malware Attack & Defense Simulation
        </p>
      </div>

      {/* Row 1 */}
      <div className="grid grid-cols-2 gap-4 mb-4">
        <AttackTimeline />
        <ThreatMeter />
      </div>

      {/* Row 2 */}
      <div className="grid grid-cols-2 gap-4 mb-4">
        <C2Graph />
        <LayerStatus />
      </div>

      {/* Row 3 */}
      <div className="grid grid-cols-2 gap-4">
        <DefensePanel />
        <AIPanel />
      </div>

    </div>
  );
}

export default Dashboard;