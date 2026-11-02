import { memo, useMemo, useState } from "react";
import {
  ReactFlow,
  Background,
  Controls,
  Handle,
  Position,
  BaseEdge,
  EdgeLabelRenderer,
  getBezierPath,
} from "@xyflow/react";
import type {
  Node,
  NodeProps,
  Edge,
  EdgeProps,
  NodeChange,
} from "@xyflow/react";
import {
  Database,
  Globe2,
  Server,
  ShieldAlert,
  CircleHelp,
  LockKeyhole,
} from "lucide-react";
import { healthLabels, layout } from "../topology";
import type { DisplayNode, DisplayEdge, Topology } from "../types";
import "@xyflow/react/dist/style.css";

type WorkNode = Node<DisplayNode & Record<string, unknown>, "workload">;
type WorkEdge = Edge<DisplayEdge & Record<string, unknown>, "signal">;
const WorkloadNode = memo(function WorkloadNode({ data }: NodeProps<WorkNode>) {
  const Icon =
    data.kind === "storage" ? Database : data.kind === "edge" ? Globe2 : Server;
  return (
    <div
      className={`workload-node ${data.health} ${data.selected ? "chosen" : ""} ${data.potential ? "potential" : ""}`}
    >
      <Handle type="target" position={Position.Left} isConnectable={false} />
      <div className="node-top">
        <span className="node-icon">
          <Icon size={18} />
        </span>
        <span className="node-kind">
          {data.lane
            ? data.lane === "blue"
              ? "SOURCE"
              : "TARGET"
            : data.kind === "storage"
              ? "DATA"
              : data.kind === "edge"
                ? "ENTRY"
                : "SERVICE"}
        </span>
        {data.health === "failed" && (
          <ShieldAlert size={15} className="problem-icon" />
        )}
        {data.health === "isolated" && (
          <LockKeyhole
            size={16}
            className="isolation-icon"
            aria-label="격리 확인"
          />
        )}
      </div>
      <strong>{data.label}</strong>
      <small>{data.subtitle}</small>
      <div className="node-status">
        <span className="status-dot" />
        {healthLabels[data.health]}
        {data.potential && (
          <CircleHelp size={12} aria-label="인접 영향 가능, 미검증" />
        )}
      </div>
      <Handle type="source" position={Position.Right} isConnectable={false} />
    </div>
  );
});
function SignalEdge(props: EdgeProps<WorkEdge>) {
  const [path, x, y] = getBezierPath(props);
  const { data } = props;
  const state = data?.state || "idle";
  return (
    <>
      <BaseEdge path={path} className={`signal-edge ${state}`} />
      <EdgeLabelRenderer>
        <span
          className={`edge-caption ${state}`}
          style={{
            transform: `translate(-50%, -50%) translate(${x}px, ${y}px)`,
          }}
        >
          {data?.label}
        </span>
      </EdgeLabelRenderer>
      {data?.requestId && state !== "idle" && state !== "cut" && (
        <circle
          key={data.requestId}
          r="3.5"
          className={`request-particle ${state}`}
        >
          <animateMotion dur="0.85s" repeatCount="1" path={path} />
        </circle>
      )}
    </>
  );
}
const nodeTypes = { workload: WorkloadNode };
const edgeTypes = { signal: SignalEdge };

export function WorkloadMap({
  topology,
  selected,
  onSelect,
  connected,
  identity,
}: {
  topology: Topology;
  selected: string[];
  onSelect: (id: string) => void;
  connected: boolean;
  identity: string;
}) {
  // Controlled nodes are rebuilt from observations. Preserve React Flow's
  // measured dimensions, otherwise each poll hides the nodes again.
  const [measurements, setMeasurements] = useState<
    Record<string, { width: number; height: number }>
  >({});
  function onNodesChange(changes: NodeChange<WorkNode>[]) {
    setMeasurements((previous) => {
      let next = previous;
      for (const change of changes) {
        if (change.type !== "dimensions" || !change.dimensions) continue;
        const key = `${identity}:${change.id}`;
        const size = change.dimensions;
        if (
          previous[key]?.width === size.width &&
          previous[key]?.height === size.height
        )
          continue;
        if (next === previous) next = { ...previous };
        next[key] = size;
      }
      return next;
    });
  }
  const positions = useMemo(() => layout(topology), [topology]);
  const nodes: WorkNode[] = topology.nodes.map((n) => ({
    id: n.key,
    type: "workload",
    position: positions[n.key] || { x: 0, y: 0 },
    data: { ...n, selected: selected.includes(n.key) },
    selected: selected.includes(n.key),
    measured: measurements[`${identity}:${n.key}`],
    ariaLabel: `${n.label}, ${healthLabels[n.health]}`,
  }));
  const edges: WorkEdge[] = topology.edges.map((e) => ({
    id: e.id,
    source: e.source,
    target: e.target,
    type: "signal",
    data: { ...e },
  }));
  return (
    <div
      className={`workload-map ${connected ? "" : "disconnected"}`}
      data-testid="workload-map"
    >
      <ReactFlow
        key={identity}
        nodes={nodes}
        onNodesChange={onNodesChange}
        edges={edges}
        nodeTypes={nodeTypes}
        edgeTypes={edgeTypes}
        nodesDraggable={false}
        nodesConnectable={false}
        edgesReconnectable={false}
        elementsSelectable={false}
        onNodeClick={(_, node) => onSelect(node.id)}
        fitView
        fitViewOptions={{ padding: 0.22, maxZoom: 1.05 }}
        minZoom={0.35}
        maxZoom={1.5}
        preventScrolling={false}
      >
        <Background color="#dce3ee" gap={22} size={1} />
        <Controls showInteractive={false} />
      </ReactFlow>
      {!topology.nodes.length && (
        <div className="map-empty">
          <Server size={28} />
          <strong>워크로드 관측을 기다리고 있습니다</strong>
          <span>확인된 자원만 지도에 표시합니다.</span>
        </div>
      )}
      <div className="map-legend">
        <span>
          <i className="green" />
          확인
        </span>
        <span>
          <i className="amber" />
          영향
        </span>
        <span>
          <i className="red" />
          문제
        </span>
        <span>
          <i className="isolated-dot" />
          격리 확인
        </span>
        <span>
          <i className="muted-dot" />
          미확인
        </span>
      </div>
    </div>
  );
}
