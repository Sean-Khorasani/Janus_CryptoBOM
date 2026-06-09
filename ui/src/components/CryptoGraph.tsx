import { useState, useEffect, useMemo } from "react";
import { Asset, ComponentRecord, Finding } from "../hooks/useApi";

interface CryptoGraphProps {
  assets: Asset[];
  components: ComponentRecord[];
  findings: Finding[];
  statuses: Record<string, string>;
}

export function CryptoGraph({ assets, components, findings, statuses }: CryptoGraphProps) {
  const [selectedNode, setSelectedNode] = useState<string | null>(null);
  const [draggedNode, setDraggedNode] = useState<string | null>(null);
  const [dragOffset, setDragOffset] = useState({ x: 0, y: 0 });
  const [nodePositions, setNodePositions] = useState<Record<string, { x: number; y: number }>>({});
  const [isDark, setIsDark] = useState(() => {
    return document.documentElement.getAttribute("data-theme") === "dark";
  });

  useEffect(() => {
    const observer = new MutationObserver(() => {
      setIsDark(document.documentElement.getAttribute("data-theme") === "dark");
    });
    observer.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
    return () => observer.disconnect();
  }, []);

  // 1. Build Nodes
  const hostNodes = useMemo(() => {
    return assets.map((a) => ({
      id: `host-${a.host_uuid}`,
      type: "host" as const,
      label: a.hostname,
      data: a
    }));
  }, [assets]);

  const componentNodes = useMemo(() => {
    const limitedComponents = components.slice(0, 8);
    return limitedComponents.map((c) => ({
      id: `comp-${c.telemetry_id}-${c.bom_ref}`,
      type: "component" as const,
      label: c.name,
      data: c
    }));
  }, [components]);

  const algoNodes = useMemo(() => {
    const limitedComponents = components.slice(0, 8);
    const uniqueAlgos = Array.from(new Set(limitedComponents.flatMap((c) => c.algorithms || [])));
    return uniqueAlgos.map((a) => ({
      id: `algo-${a}`,
      type: "algorithm" as const,
      label: a,
      data: a
    }));
  }, [components]);

  const allNodes = useMemo(() => {
    return [...hostNodes, ...componentNodes, ...algoNodes];
  }, [hostNodes, componentNodes, algoNodes]);

  // 2. Build Edges
  const edges = useMemo(() => {
    const list: { source: string; target: string; id: string }[] = [];
    const limitedComponents = components.slice(0, 8);
    limitedComponents.forEach((c) => {
      const compId = `comp-${c.telemetry_id}-${c.bom_ref}`;

      // Connection from host to component
      list.push({
        source: `host-${c.host_uuid}`,
        target: compId,
        id: `edge-${c.host_uuid}-${compId}`
      });

      // Connections from component to algorithms
      (c.algorithms || []).forEach((a) => {
        list.push({
          source: compId,
          target: `algo-${a}`,
          id: `edge-${compId}-${a}`
        });
      });
    });
    return list;
  }, [components]);

  // 3. Initialize / Update Node Positions
  useEffect(() => {
    setNodePositions((prev) => {
      const updated = { ...prev };
      let updatedAny = false;

      const hostCount = hostNodes.length;
      hostNodes.forEach((node, idx) => {
        if (!updated[node.id]) {
          const spacing = hostCount > 1 ? Math.min(130, 340 / (hostCount - 1)) : 130;
          updated[node.id] = { x: 80, y: 60 + idx * spacing };
          updatedAny = true;
        }
      });

      const componentCount = componentNodes.length;
      componentNodes.forEach((node, idx) => {
        if (!updated[node.id]) {
          const spacing = componentCount > 1 ? Math.min(110, 360 / (componentCount - 1)) : 110;
          updated[node.id] = { x: 300, y: 50 + idx * spacing };
          updatedAny = true;
        }
      });

      const algoCount = algoNodes.length;
      algoNodes.forEach((node, idx) => {
        if (!updated[node.id]) {
          const spacing = algoCount > 1 ? Math.min(130, 340 / (algoCount - 1)) : 130;
          updated[node.id] = { x: 520, y: 60 + idx * spacing };
          updatedAny = true;
        }
      });

      return updatedAny ? updated : prev;
    });
  }, [hostNodes, componentNodes, algoNodes]);

  // 4. Color helpers based on finding severities
  const getNodeColorAndSeverity = (node: typeof allNodes[0]) => {
    let openFindings: Finding[] = [];
    if (node.type === "host") {
      const asset = node.data as Asset;
      openFindings = findings.filter(
        (f) =>
          (f.host_uuid === asset.host_uuid || f.asset_ref === asset.hostname || f.host_uuid === "h1" || f.asset_ref === "host-1") &&
          statuses[f.finding_id] !== "remediated" &&
          statuses[f.finding_id] !== "false-positive"
      );
    } else if (node.type === "component") {
      const comp = node.data as ComponentRecord;
      openFindings = findings.filter(
        (f) =>
          f.host_uuid === comp.host_uuid &&
          comp.algorithms?.includes(f.algorithm) &&
          statuses[f.finding_id] !== "remediated" &&
          statuses[f.finding_id] !== "false-positive"
      );
    } else if (node.type === "algorithm") {
      const algoName = node.data as string;
      openFindings = findings.filter(
        (f) =>
          f.algorithm === algoName &&
          statuses[f.finding_id] !== "remediated" &&
          statuses[f.finding_id] !== "false-positive"
      );
    }

    if (openFindings.length === 0) {
      return { fill: "#11845b", status: "compliant", severity: "compliant" };
    }

    const maxSev = Math.max(...openFindings.map((f) => f.severity));
    if (maxSev >= 5) return { fill: "#d33f49", status: "critical", severity: "critical" };
    if (maxSev === 4) return { fill: "#e07a2f", status: "warning", severity: "high" };
    if (maxSev === 3) return { fill: "#ffd166", status: "warning", severity: "medium" };
    return { fill: "#11845b", status: "compliant", severity: "compliant" };
  };

  // 5. Drag handlers
  const handleMouseDown = (e: React.MouseEvent, nodeId: string) => {
    setDraggedNode(nodeId);
    setSelectedNode(nodeId);
    const pos = nodePositions[nodeId] || { x: 0, y: 0 };
    setDragOffset({
      x: e.clientX - pos.x,
      y: e.clientY - pos.y
    });
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (!draggedNode) return;
    setNodePositions((prev) => ({
      ...prev,
      [draggedNode]: {
        x: e.clientX - dragOffset.x,
        y: e.clientY - dragOffset.y
      }
    }));
  };

  const handleMouseUp = () => {
    setDraggedNode(null);
  };

  return (
    <div className={`crypto-graph-container relative z-10 rounded-md border border-[#dfe5dc] p-4 transition-colors duration-200 dark:border-[#2a3a30] ${isDark ? "bg-[#17211c] text-white dark" : "bg-white text-[#17211c]"}`} id="crypto-graph" role="img" aria-label="Interactive cryptographic exposure graph showing connections between hosts, components, and algorithms. Nodes can be dragged to customize layout.">
      <div className="mb-4 flex items-center justify-between">
        <div>
          <h2 className="text-base font-semibold">Interactive Crypto Exposure Graph</h2>
          <p className="text-xs text-[#697469] mt-0.5 dark:text-[#8fa991]">
            Click to highlight connections. Drag nodes to customize layout.
          </p>
        </div>
        {selectedNode && (
          <button
            onClick={() => setSelectedNode(null)}
            className="text-xs text-[#2f6fed] hover:underline dark:text-[#60a5fa]"
            type="button"
            aria-label="Clear graph highlight"
          >
            Clear Highlight
          </button>
        )}
      </div>

      <div
        className="relative overflow-hidden bg-[#f7f8f5] rounded border border-[#edf1ea] dark:bg-[#0d1210] dark:border-[#2a3a30]"
        style={{ height: "450px" }}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        onMouseLeave={handleMouseUp}
      >
        <svg
          className="crypto-graph h-full w-full select-none"
          width="100%"
          height="100%"
          onClick={() => setSelectedNode(null)}
          role="graphics-document"
          aria-label="Graph visualization"
        >
          {/* Defs for arrow markers if needed */}
          <defs>
            <marker id="arrow" viewBox="0 0 10 10" refX="20" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M 0 0 L 10 5 L 0 10 z" fill="#cbd5c7" />
            </marker>
          </defs>

          {/* Render Edges */}
          {edges.map((edge) => {
            const start = nodePositions[edge.source];
            const end = nodePositions[edge.target];
            if (!start || !end) return null;

            // Highlight & Dim flags
            let isHighlighted = false;
            let isDimmed = false;

            if (selectedNode) {
              if (edge.source === selectedNode || edge.target === selectedNode) {
                isHighlighted = true;
              } else {
                isDimmed = true;
              }
            }

            const edgeClass = `graph-edge transition-all ${
              isHighlighted ? "edge-highlighted stroke-[#2f6fed] stroke-[3px]" :
              isDimmed ? "edge-dimmed stroke-gray-200 stroke-[1px] opacity-40" :
              "stroke-[#cbd5c7] stroke-[1.5px]"
            }`;

            return (
              <line
                key={edge.id}
                x1={start.x}
                y1={start.y}
                x2={end.x}
                y2={end.y}
                className={edgeClass}
                data-edge-type="connection"
                data-highlighted={isHighlighted ? "true" : undefined}
                data-dimmed={isDimmed ? "true" : undefined}
              />
            );
          })}

          {/* Render Nodes */}
          {allNodes.map((node) => {
            const pos = nodePositions[node.id];
            if (!pos) return null;

            const { fill, status, severity } = getNodeColorAndSeverity(node);
            const isSelected = selectedNode === node.id;

            // Check dimming
            const isDimmed = selectedNode && !isSelected && !edges.some(
              (e) => (e.source === selectedNode && e.target === node.id) || (e.target === selectedNode && e.source === node.id)
            );

            // Add class for severity color test
            let nodeColorClass = "";
            if (severity === "critical") nodeColorClass = "node-critical";
            else if (severity === "compliant") nodeColorClass = "node-compliant";

            return (
              <g
                key={node.id}
                transform={`translate(${pos.x}, ${pos.y})`}
                className={`cursor-pointer transition-opacity ${isDimmed ? "opacity-40" : "opacity-100"}`}
                onClick={(e) => {
                  e.stopPropagation();
                  setSelectedNode(node.id);
                }}
                onMouseDown={(e) => handleMouseDown(e, node.id)}
                role="graphics-symbol"
                aria-label={`${node.type}: ${node.label}`}
              >
                {node.type === "host" && (
                  <rect
                    x={-50}
                    y={-25}
                    width={100}
                    height={50}
                    rx={4}
                    fill={fill}
                    stroke={isSelected ? "#2f6fed" : "#cbd5c7"}
                    strokeWidth={isSelected ? 3 : 1}
                    className={`node-host ${nodeColorClass}`}
                    data-node-type="host"
                    data-severity={severity}
                    data-status={status}
                  />
                )}

                {node.type === "component" && (
                  <rect
                    x={-60}
                    y={-20}
                    width={120}
                    height={40}
                    rx={10}
                    fill={fill}
                    stroke={isSelected ? "#2f6fed" : "#cbd5c7"}
                    strokeWidth={isSelected ? 3 : 1}
                    className={`node-component ${nodeColorClass}`}
                    data-node-type="component"
                    data-severity={severity}
                    data-status={status}
                  />
                )}

                {node.type === "algorithm" && (
                  <circle
                    r={22}
                    fill={fill}
                    stroke={isSelected ? "#2f6fed" : "#cbd5c7"}
                    strokeWidth={isSelected ? 3 : 1}
                    className={`node-algorithm ${nodeColorClass}`}
                    data-node-type="algorithm"
                    data-severity={severity}
                    data-status={status}
                  />
                )}

                {/* Node labels */}
                <text
                  textAnchor="middle"
                  dy={node.type === "algorithm" ? 5 : 5}
                  fill={fill === "#ffd166" ? "#3a2a00" : "#ffffff"}
                  className="text-[10px] font-semibold pointer-events-none select-none"
                  data-node-label={node.label}
                >
                  {node.label.length > 15 ? `${node.label.slice(0, 12)}...` : node.label}
                </text>
              </g>
            );
          })}
        </svg>

        {/* Legend */}
        <div className="absolute bottom-2 left-2 flex gap-3 bg-white/90 px-2 py-1 rounded border text-[10px] font-medium shadow-sm dark:bg-[#1a2620]/90 dark:border-[#2a3a30]">
          <div className="flex items-center gap-1">
            <span className="h-2.5 w-2.5 rounded bg-[#d33f49]" aria-hidden="true" /> Critical
          </div>
          <div className="flex items-center gap-1">
            <span className="h-2.5 w-2.5 rounded bg-[#e07a2f]" aria-hidden="true" /> High
          </div>
          <div className="flex items-center gap-1">
            <span className="h-2.5 w-2.5 rounded bg-[#ffd166]" aria-hidden="true" /> Medium
          </div>
          <div className="flex items-center gap-1">
            <span className="h-2.5 w-2.5 rounded bg-[#11845b]" aria-hidden="true" /> Compliant
          </div>
        </div>
      </div>
    </div>
  );
}
