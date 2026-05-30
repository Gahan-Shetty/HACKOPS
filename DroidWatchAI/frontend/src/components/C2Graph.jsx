import React, { useEffect, useRef } from 'react';
import cytoscape from 'cytoscape';

function C2Graph() {
  const cyRef = useRef(null);

  useEffect(() => {
    const cy = cytoscape({
      container: cyRef.current,
      elements: [
        { data: { id: 'device', label: '📱 Device' } },
        { data: { id: 'c2', label: '☠️ C2 Server' } },
        { data: { id: 'dns', label: '🌐 DNS Server' } },
        { data: { id: 'ip1', label: '⚠️ Suspicious IP' } },
        { data: { source: 'device', target: 'c2' } },
        { data: { source: 'device', target: 'dns' } },
        { data: { source: 'device', target: 'ip1' } },
      ],
      style: [
        { selector: 'node', style: {
          'background-color': '#1e40af',
          'label': 'data(label)',
          'color': '#ffffff',
          'font-size': '11px',
          'text-valign': 'bottom',
          'text-margin-y': '5px',
        }},
        { selector: 'edge', style: {
          'width': 2,
          'line-color': '#ef4444',
          'target-arrow-color': '#ef4444',
          'target-arrow-shape': 'triangle',
          'curve-style': 'bezier',
        }},
      ],
      layout: { name: 'circle' },
      userZoomingEnabled: false,
    });

    return () => cy.destroy();
  }, []);

  return (
    <div className="bg-gray-900 rounded-xl p-4 border border-gray-700">
      <h2 className="text-white font-bold text-lg mb-4">🕸️ C2 Network Graph</h2>
      <div ref={cyRef} style={{ height: '250px', backgroundColor: '#111827', borderRadius: '8px' }} />
    </div>
  );
}

export default C2Graph;