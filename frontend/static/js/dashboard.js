"use strict";

document.addEventListener("DOMContentLoaded", () => {
  const byId = (id) => document.getElementById(id);

  const splash = byId("splash");
  const select = byId("interface-select");
  const message = byId("interface-message");
  const refreshButton = byId("refresh-interfaces");
  const startButton = byId("start-capture");
  const stopButton = byId("stop-capture");

  const captureState = byId("capture-state");
  const captureInterface = byId("capture-interface");
  const captureDot = byId("capture-status-dot");

  const packetsValue = byId("packets-value");
  const flowsValue = byId("flows-value");
  const trafficValue = byId("traffic-value");
  const alertsValue = byId("alerts-value");

  const packetsBody = byId("packets-body");
  const flowsBody = byId("flows-body");
  const alertsBody = byId("alerts-body");
  const historyBody = byId("history-body");

  const packetSearch = byId("packet-search");
  const packetProtocol = byId("packet-protocol");
  const clearPacketFilters = byId("clear-packet-filters");
  const packetResultsCount = byId("packet-results-count");
  const exportPacketsButton = byId("export-packets");

  const flowSearch = byId("flow-search");
  const flowProtocol = byId("flow-protocol");
  const clearFlowFilters = byId("clear-flow-filters");
  const flowResultsCount = byId("flow-results-count");
  const exportFlowsButton = byId("export-flows");

  const protocolBreakdown = byId("protocol-breakdown");
  const trafficChart = byId("traffic-chart");
  const trafficRate = byId("traffic-rate");
  const trafficChartMessage = byId("traffic-chart-message");

  if (splash) {
    const reduceMotion = window.matchMedia(
      "(prefers-reduced-motion: reduce)"
    ).matches;

    window.setTimeout(() => {
      splash.classList.add("splash--hidden");
      splash.setAttribute("aria-hidden", "true");
    }, reduceMotion ? 100 : 1000);
  }

  if (!select || !refreshButton || !startButton || !stopButton) {
    return;
  }

  const chartHistory = [];
  const maxChartPoints = 40;

  let statusTimer = null;
  let lastStatus = {
    status: "IDLE",
    packet_count: 0,
    bytes_captured: 0,
  };

  let latestPackets = [];
  let latestFlows = [];
  let previousBytes = null;
  let flowDialog = null;
  let alertDialog = null;
  let archiveDialog = null;
  let archiveShownCount = 100;

  let flowSort = {
    key: "last_seen",
    direction: "desc",
  };

  async function requestJson(url, options = {}) {
    const response = await fetch(url, options);
    const rawBody = await response.text();

    let data = {};

    if (rawBody) {
      try {
        data = JSON.parse(rawBody);
      } catch {
        throw new Error("Le serveur a renvoyé une réponse invalide.");
      }
    }

    if (!response.ok) {
      const detail = data.detail;
      const errorMessage = Array.isArray(detail)
        ? detail.map((item) => item.msg || "Erreur de validation").join(", ")
        : detail || `La requête a échoué (${response.status}).`;

      throw new Error(errorMessage);
    }

    return data;
  }

  function formatNumber(value) {
    return Number(value || 0).toLocaleString("fr-FR");
  }

  function formatBytes(value) {
    const bytes = Number(value || 0);

    if (bytes < 1024) {
      return `${formatNumber(bytes)} o`;
    }

    if (bytes < 1024 * 1024) {
      return `${(bytes / 1024).toLocaleString("fr-FR", {
        maximumFractionDigits: 1,
      })} Ko`;
    }

    if (bytes < 1024 * 1024 * 1024) {
      return `${(bytes / (1024 * 1024)).toLocaleString("fr-FR", {
        maximumFractionDigits: 1,
      })} Mo`;
    }

    return `${(bytes / (1024 * 1024 * 1024)).toLocaleString("fr-FR", {
      maximumFractionDigits: 1,
    })} Go`;
  }

  function formatDateTime(value) {
    if (!value) return "—";

    const date = new Date(value);

    return Number.isNaN(date.getTime())
      ? "—"
      : date.toLocaleString("fr-FR");
  }

  function formatTime(value) {
    if (!value) return "—";

    const date = new Date(value);

    return Number.isNaN(date.getTime())
      ? "—"
      : date.toLocaleTimeString("fr-FR");
  }

  function formatEndpoint(ip, port) {
    if (!ip) return "Non disponible";

    if (port === null || port === undefined || port === "") {
      return String(ip);
    }

    const address = String(ip).includes(":") ? `[${ip}]` : ip;
    return `${address}:${port}`;
  }

  function addCell(row, value, className = "") {
    const cell = document.createElement("td");

    cell.textContent =
      value === null || value === undefined ? "—" : String(value);

    if (className) {
      cell.className = className;
    }

    row.appendChild(cell);
    return cell;
  }

  function setEmptyRow(tbody, columnCount, text) {
    if (!tbody) return;

    tbody.replaceChildren();

    const row = document.createElement("tr");
    const cell = document.createElement("td");

    cell.colSpan = columnCount;
    cell.className = "table-empty";
    cell.textContent = text;

    row.appendChild(cell);
    tbody.appendChild(row);
  }

  function normalizeProtocol(value) {
    return String(value || "INCONNU").trim().toUpperCase();
  }

  function updateProtocolSelect(selectElement, values, defaultLabel) {
    if (!selectElement) return;

    const previousValue = selectElement.value;
    const protocols = [...new Set(values.map(normalizeProtocol))].sort();

    selectElement.replaceChildren(new Option(defaultLabel, ""));

    for (const protocol of protocols) {
      selectElement.add(new Option(protocol, protocol));
    }

    if (protocols.includes(previousValue)) {
      selectElement.value = previousValue;
    }
  }

  function escapeCsvCell(value) {
    return `"${String(value ?? "").replaceAll('"', '""')}"`;
  }

  function downloadCsv(filename, columns, rows) {
    const csv = [columns, ...rows]
      .map((row) => row.map(escapeCsvCell).join(";"))
      .join("\r\n");

    const blob = new Blob(["\uFEFF", csv], {
      type: "text/csv;charset=utf-8",
    });

    const downloadUrl = URL.createObjectURL(blob);
    const link = document.createElement("a");

    link.href = downloadUrl;
    link.download = filename;

    document.body.appendChild(link);
    link.click();
    link.remove();

    window.setTimeout(() => URL.revokeObjectURL(downloadUrl), 1000);
  }

  function getFilteredPackets() {
    const searchTerm = packetSearch
      ? packetSearch.value.trim().toLowerCase()
      : "";

    const selectedProtocol = packetProtocol
      ? packetProtocol.value.toUpperCase()
      : "";

    return latestPackets.filter((packet) => {
      const protocol = normalizeProtocol(packet.protocol);
      const transport = normalizeProtocol(packet.transport_protocol);
      const application = normalizeProtocol(packet.application_protocol);

      if (
        selectedProtocol &&
        protocol !== selectedProtocol &&
        transport !== selectedProtocol &&
        application !== selectedProtocol
      ) {
        return false;
      }

      if (!searchTerm) return true;

      const searchableValues = [
        packet.source_ip,
        packet.destination_ip,
        packet.source_port,
        packet.destination_port,
        packet.protocol,
        packet.transport_protocol,
        packet.application_protocol,
        packet.packet_length_bytes,
        packet.timestamp,
        ...(Array.isArray(packet.tcp_flags) ? packet.tcp_flags : []),
      ];

      return searchableValues
        .filter((value) => value !== null && value !== undefined)
        .join(" ")
        .toLowerCase()
        .includes(searchTerm);
    });
  }

  function exportVisiblePackets() {
    const packets = getFilteredPackets();

    if (packets.length === 0) {
      if (message) message.textContent = "Aucun paquet à exporter.";
      return;
    }

    const columns = [
      "Horodatage",
      "Adresse source",
      "Port source",
      "Adresse destination",
      "Port destination",
      "Protocole",
      "Protocole transport",
      "Protocole application",
      "Indicateurs TCP",
      "Taille en octets",
      "TTL",
      "Version IP",
      "Identifiant paquet",
    ];

    const rows = packets.map((packet) => [
      packet.timestamp || "",
      packet.source_ip || "",
      packet.source_port ?? "",
      packet.destination_ip || "",
      packet.destination_port ?? "",
      packet.protocol || "",
      packet.transport_protocol || "",
      packet.application_protocol || "",
      Array.isArray(packet.tcp_flags) ? packet.tcp_flags.join(", ") : "",
      packet.packet_length_bytes ?? "",
      packet.ttl ?? "",
      packet.ip_version ?? "",
      packet.packet_id || "",
    ]);

    const timestamp = new Date().toISOString().replaceAll(":", "-");
    downloadCsv(`paquets-recents-${timestamp}.csv`, columns, rows);
  }

  function getFlowSortValue(flow, key) {
    const endpointA = flow.endpoint_a || {};
    const endpointB = flow.endpoint_b || {};

    switch (key) {
      case "endpoint_a":
        return `${endpointA.ip || ""}:${endpointA.port ?? ""}`.toLowerCase();
      case "endpoint_b":
        return `${endpointB.ip || ""}:${endpointB.port ?? ""}`.toLowerCase();
      case "protocol":
        return String(flow.protocol || "").toLowerCase();
      case "packet_count":
        return Number(flow.packet_count || 0);
      case "bytes_total":
        return Number(flow.bytes_total || 0);
      case "last_seen": {
        const timestamp = new Date(flow.last_seen || 0).getTime();
        return Number.isNaN(timestamp) ? 0 : timestamp;
      }
      default:
        return 0;
    }
  }

  function getFilteredAndSortedFlows() {
    const searchTerm = flowSearch
      ? flowSearch.value.trim().toLowerCase()
      : "";

    const selectedProtocol = flowProtocol
      ? flowProtocol.value.toUpperCase()
      : "";

    const filteredFlows = latestFlows.filter((flow) => {
      const protocol = normalizeProtocol(flow.protocol);

      if (selectedProtocol && protocol !== selectedProtocol) {
        return false;
      }

      if (!searchTerm) return true;

      const endpointA = flow.endpoint_a || {};
      const endpointB = flow.endpoint_b || {};

      const searchableValues = [
        endpointA.ip,
        endpointA.port,
        endpointB.ip,
        endpointB.port,
        flow.protocol,
        flow.packet_count,
        flow.bytes_total,
        flow.first_seen,
        flow.last_seen,
      ];

      return searchableValues
        .filter((value) => value !== null && value !== undefined)
        .join(" ")
        .toLowerCase()
        .includes(searchTerm);
    });

    filteredFlows.sort((first, second) => {
      const left = getFlowSortValue(first, flowSort.key);
      const right = getFlowSortValue(second, flowSort.key);

      if (left < right) {
        return flowSort.direction === "asc" ? -1 : 1;
      }

      if (left > right) {
        return flowSort.direction === "asc" ? 1 : -1;
      }

      return 0;
    });

    return filteredFlows;
  }

  function exportVisibleFlows() {
    const flows = getFilteredAndSortedFlows();

    if (flows.length === 0) {
      if (message) message.textContent = "Aucune communication à exporter.";
      return;
    }

    const columns = [
      "Dernière activité",
      "Extrémité A",
      "Extrémité B",
      "Protocole",
      "Paquets",
      "Volume en octets",
      "Première activité",
    ];

    const rows = flows.map((flow) => {
      const endpointA = flow.endpoint_a || {};
      const endpointB = flow.endpoint_b || {};

      return [
        formatDateTime(flow.last_seen),
        formatEndpoint(endpointA.ip, endpointA.port),
        formatEndpoint(endpointB.ip, endpointB.port),
        flow.protocol || "Inconnu",
        flow.packet_count ?? 0,
        flow.bytes_total ?? 0,
        formatDateTime(flow.first_seen),
      ];
    });

    const timestamp = new Date().toISOString().replaceAll(":", "-");
    downloadCsv(`communications-${timestamp}.csv`, columns, rows);
  }

  function ensureFlowDialog() {
    if (flowDialog) return flowDialog;

    const style = document.createElement("style");
    style.textContent = `
      .flow-detail-dialog {
        width: min(560px, calc(100vw - 32px));
        max-height: min(80vh, 720px);
        overflow: auto;
        padding: 0;
        color: #e5edf3;
        background: #08131e;
        border: 1px solid rgba(145, 170, 188, 0.28);
        border-radius: 18px;
        box-shadow: 0 24px 80px rgba(0, 0, 0, 0.55);
      }

      .flow-detail-dialog::backdrop {
        background: rgba(1, 7, 12, 0.78);
        backdrop-filter: blur(4px);
      }

      .flow-detail-dialog__content {
        padding: 24px;
      }

      .flow-detail-dialog__header {
        display: flex;
        align-items: flex-start;
        justify-content: space-between;
        gap: 16px;
        margin-bottom: 22px;
      }

      .flow-detail-dialog__header h2 {
        margin: 4px 0 0;
        font-size: 1.35rem;
      }

      .flow-detail-dialog__close {
        min-width: 40px;
        min-height: 40px;
        color: #dce8ef;
        background: rgba(255, 255, 255, 0.05);
        border: 1px solid rgba(145, 170, 188, 0.25);
        border-radius: 10px;
        cursor: pointer;
        font-size: 1.25rem;
      }

      .flow-detail-dialog__grid {
        display: grid;
        grid-template-columns: repeat(2, minmax(0, 1fr));
        gap: 12px;
      }

      .flow-detail-dialog__item {
        min-width: 0;
        padding: 14px;
        background: rgba(255, 255, 255, 0.035);
        border: 1px solid rgba(145, 170, 188, 0.15);
        border-radius: 12px;
      }

      .flow-detail-dialog__item--wide {
        grid-column: 1 / -1;
      }

      .flow-detail-dialog__label {
        display: block;
        margin-bottom: 7px;
        color: #95aab8;
        font-size: 0.75rem;
        font-weight: 700;
        letter-spacing: 0.06em;
        text-transform: uppercase;
      }

      .flow-detail-dialog__value {
        overflow-wrap: anywhere;
        font-weight: 600;
      }

      .flow-table tbody tr[data-flow-row="true"] {
        cursor: pointer;
      }

      .flow-table tbody tr[data-flow-row="true"]:hover {
        background: rgba(72, 214, 229, 0.07);
      }

      .flow-table tbody tr[data-flow-row="true"]:focus {
        outline: 2px solid #48d6e5;
        outline-offset: -2px;
      }

      .history-export-link {
        display: inline-block;
        text-decoration: none;
        white-space: nowrap;
      }

      @media (max-width: 520px) {
        .flow-detail-dialog__grid {
          grid-template-columns: 1fr;
        }

        .flow-detail-dialog__item--wide {
          grid-column: auto;
        }
      }
    `;

    document.head.appendChild(style);

    flowDialog = document.createElement("dialog");
    flowDialog.id = "flow-detail-dialog";
    flowDialog.className = "flow-detail-dialog";
    flowDialog.setAttribute("aria-labelledby", "flow-detail-title");

    flowDialog.innerHTML = `
      <div class="flow-detail-dialog__content">
        <div class="flow-detail-dialog__header">
          <div>
            <p class="eyebrow">DÉTAIL DE LA COMMUNICATION</p>
            <h2 id="flow-detail-title">Communication réseau</h2>
          </div>
          <button
            class="flow-detail-dialog__close"
            type="button"
            aria-label="Fermer les détails"
          >×</button>
        </div>

        <div class="flow-detail-dialog__grid">
          <div class="flow-detail-dialog__item">
            <span class="flow-detail-dialog__label">Protocole</span>
            <div class="flow-detail-dialog__value" data-flow-detail="protocol"></div>
          </div>

          <div class="flow-detail-dialog__item">
            <span class="flow-detail-dialog__label">Identifiant</span>
            <div class="flow-detail-dialog__value" data-flow-detail="id"></div>
          </div>

          <div class="flow-detail-dialog__item flow-detail-dialog__item--wide">
            <span class="flow-detail-dialog__label">Extrémité A</span>
            <div class="flow-detail-dialog__value" data-flow-detail="endpoint-a"></div>
          </div>

          <div class="flow-detail-dialog__item flow-detail-dialog__item--wide">
            <span class="flow-detail-dialog__label">Extrémité B</span>
            <div class="flow-detail-dialog__value" data-flow-detail="endpoint-b"></div>
          </div>

          <div class="flow-detail-dialog__item">
            <span class="flow-detail-dialog__label">Paquets</span>
            <div class="flow-detail-dialog__value" data-flow-detail="packets"></div>
          </div>

          <div class="flow-detail-dialog__item">
            <span class="flow-detail-dialog__label">Volume</span>
            <div class="flow-detail-dialog__value" data-flow-detail="volume"></div>
          </div>

          <div class="flow-detail-dialog__item">
            <span class="flow-detail-dialog__label">Première activité</span>
            <div class="flow-detail-dialog__value" data-flow-detail="first-seen"></div>
          </div>

          <div class="flow-detail-dialog__item">
            <span class="flow-detail-dialog__label">Dernière activité</span>
            <div class="flow-detail-dialog__value" data-flow-detail="last-seen"></div>
          </div>
        </div>
      </div>
    `;

    document.body.appendChild(flowDialog);

    flowDialog
      .querySelector(".flow-detail-dialog__close")
      .addEventListener("click", () => flowDialog.close());

    flowDialog.addEventListener("click", (event) => {
      if (event.target === flowDialog) {
        flowDialog.close();
      }
    });

    return flowDialog;
  }

  function showFlowDetails(flow) {
    const dialog = ensureFlowDialog();
    const endpointA = flow.endpoint_a || {};
    const endpointB = flow.endpoint_b || {};

    const values = {
      protocol: flow.protocol || "Inconnu",
      id: flow.flow_id ?? "—",
      "endpoint-a": formatEndpoint(endpointA.ip, endpointA.port),
      "endpoint-b": formatEndpoint(endpointB.ip, endpointB.port),
      packets: formatNumber(flow.packet_count),
      volume: formatBytes(flow.bytes_total),
      "first-seen": formatDateTime(flow.first_seen),
      "last-seen": formatDateTime(flow.last_seen),
    };

    for (const [key, value] of Object.entries(values)) {
      const element = dialog.querySelector(
        `[data-flow-detail="${key}"]`
      );

      if (element) {
        element.textContent = value;
      }
    }

    if (typeof dialog.showModal === "function") {
      dialog.showModal();
    } else {
      dialog.setAttribute("open", "");
    }
  }

  function displayPackets() {
    if (!packetsBody) return;

    const packets = getFilteredPackets();

    if (packetResultsCount) {
      packetResultsCount.textContent =
        `${formatNumber(packets.length)} résultat(s) sur ` +
        `${formatNumber(latestPackets.length)} paquet(s) récent(s).`;
    }

    if (exportPacketsButton) {
      exportPacketsButton.disabled = packets.length === 0;
    }

    if (packets.length === 0) {
      setEmptyRow(
        packetsBody,
        6,
        latestPackets.length === 0
          ? "Aucun paquet récent dans cette session."
          : "Aucun paquet ne correspond aux filtres."
      );
      return;
    }

    packetsBody.replaceChildren();

    for (const packet of packets) {
      const row = document.createElement("tr");
      const flags =
        Array.isArray(packet.tcp_flags) && packet.tcp_flags.length
          ? packet.tcp_flags.join(", ")
          : "—";
      const protocol = packet.protocol || "Inconnu";
      const transport = packet.transport_protocol
        ? ` (${packet.transport_protocol})`
        : "";

      addCell(row, formatTime(packet.timestamp));
      addCell(
        row,
        formatEndpoint(packet.source_ip, packet.source_port),
        "address-cell"
      );
      addCell(
        row,
        formatEndpoint(packet.destination_ip, packet.destination_port),
        "address-cell"
      );
      addCell(row, `${protocol}${transport}`, "protocol-cell");
      addCell(row, flags);

      const size = packet.packet_length_bytes;
      addCell(row, size == null ? "—" : formatBytes(size));

      packetsBody.appendChild(row);
    }
  }

  function updateFlowSortIndicators() {
    const headers = document.querySelectorAll(".flow-table thead th");
    const sortKeys = [
      "last_seen",
      "endpoint_a",
      "endpoint_b",
      "protocol",
      "packet_count",
      "bytes_total",
    ];

    headers.forEach((header, index) => {
      header.removeAttribute("aria-sort");

      if (sortKeys[index] === flowSort.key) {
        header.setAttribute(
          "aria-sort",
          flowSort.direction === "asc" ? "ascending" : "descending"
        );
      }
    });
  }

  function displayFlows() {
    if (!flowsBody) return;

    const flows = getFilteredAndSortedFlows();

    if (flowResultsCount) {
      flowResultsCount.textContent =
        `${formatNumber(flows.length)} communication(s) affichée(s) ` +
        `sur ${formatNumber(latestFlows.length)} chargée(s).`;
    }

    if (exportFlowsButton) {
      exportFlowsButton.disabled = flows.length === 0;
    }

    updateFlowSortIndicators();

    if (flows.length === 0) {
      setEmptyRow(
        flowsBody,
        6,
        latestFlows.length === 0
          ? "En attente de communications réseau."
          : "Aucune communication ne correspond aux filtres."
      );
      return;
    }

    flowsBody.replaceChildren();

    for (const flow of flows) {
      const row = document.createElement("tr");
      const endpointA = flow.endpoint_a || {};
      const endpointB = flow.endpoint_b || {};

      row.dataset.flowRow = "true";
      row.tabIndex = 0;
      row.setAttribute("role", "button");
      row.setAttribute(
        "aria-label",
        `Afficher les détails de la communication ${flow.protocol || ""}, ` +
          `${formatEndpoint(endpointA.ip, endpointA.port)} vers ` +
          `${formatEndpoint(endpointB.ip, endpointB.port)}`
      );

      row.addEventListener("click", () => showFlowDetails(flow));
      row.addEventListener("keydown", (event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          showFlowDetails(flow);
        }
      });

      addCell(row, formatTime(flow.last_seen));
      addCell(
        row,
        formatEndpoint(endpointA.ip, endpointA.port),
        "address-cell"
      );
      addCell(
        row,
        formatEndpoint(endpointB.ip, endpointB.port),
        "address-cell"
      );
      addCell(row, flow.protocol || "Inconnu", "protocol-cell");
      addCell(row, formatNumber(flow.packet_count));
      addCell(row, formatBytes(flow.bytes_total));

      flowsBody.appendChild(row);
    }
  }

  function displayProtocols(flows) {
    if (flowsValue) {
      flowsValue.textContent = formatNumber(flows.length);
    }

    if (!protocolBreakdown) return;

    if (flows.length === 0) {
      protocolBreakdown.innerHTML = `
        <div class="empty-state">
          <span class="protocol-ring">—</span>
          <strong>Pas encore de données</strong>
          <small>La répartition apparaîtra pendant ou après une capture.</small>
        </div>
      `;
      return;
    }

    const totals = new Map();

    for (const flow of flows) {
      const protocol = normalizeProtocol(flow.protocol);
      totals.set(
        protocol,
        (totals.get(protocol) || 0) + Number(flow.packet_count || 0)
      );
    }

    const entries = [...totals.entries()].sort(
      (first, second) => second[1] - first[1]
    );
    const maximum = Math.max(...entries.map((entry) => entry[1]), 1);

    protocolBreakdown.replaceChildren();

    for (const [protocol, count] of entries) {
      const item = document.createElement("div");
      item.className = "protocol-item";

      const heading = document.createElement("div");
      heading.className = "protocol-item__heading";

      const name = document.createElement("strong");
      name.textContent = protocol;

      const value = document.createElement("span");
      value.textContent = formatNumber(count);

      heading.append(name, value);

      const track = document.createElement("div");
      track.className = "protocol-bar";

      const bar = document.createElement("span");
      bar.className = "protocol-bar__fill";
      bar.style.width = `${Math.max(2, (count / maximum) * 100)}%`;

      track.appendChild(bar);
      item.append(heading, track);
      protocolBreakdown.appendChild(item);
    }
  }

  function ensureAlertDialog() {
    if (alertDialog) return alertDialog;

    const style = document.createElement("style");
    style.textContent = `
      .alert-detail-dialog {
        width: min(760px, calc(100vw - 32px));
        max-height: min(82vh, 760px);
        overflow: auto;
        padding: 0;
        color: #e5edf3;
        background: #08131e;
        border: 1px solid rgba(145, 170, 188, .28);
        border-radius: 18px;
        box-shadow: 0 24px 80px rgba(0, 0, 0, .55);
      }
      .alert-detail-dialog::backdrop { background: rgba(1, 7, 12, .78); backdrop-filter: blur(4px); }
      .alert-detail-dialog__content { padding: 24px; }
      .alert-detail-dialog__header { display: flex; justify-content: space-between; gap: 16px; margin-bottom: 18px; }
      .alert-detail-dialog__header h2 { margin: 4px 0 0; }
      .alert-detail-dialog__close { min-width: 40px; min-height: 40px; cursor: pointer; }
      .alert-detail-dialog__grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; }
      .alert-detail-dialog__item { min-width: 0; padding: 14px; background: rgba(255,255,255,.035); border: 1px solid rgba(145,170,188,.15); border-radius: 12px; }
      .alert-detail-dialog__item--wide { grid-column: 1 / -1; }
      .alert-detail-dialog__label { display: block; margin-bottom: 7px; color: #95aab8; font-size: .75rem; font-weight: 700; letter-spacing: .06em; text-transform: uppercase; }
      .alert-detail-dialog__value { overflow-wrap: anywhere; white-space: pre-wrap; }
      .alert-table tbody tr[data-alert-row="true"] { cursor: pointer; }
      .alert-table tbody tr[data-alert-row="true"]:hover { background: rgba(72, 214, 229, .07); }
      .alert-table tbody tr[data-alert-row="true"]:focus { outline: 2px solid #48d6e5; outline-offset: -2px; }
      @media (max-width: 560px) { .alert-detail-dialog__grid { grid-template-columns: 1fr; } .alert-detail-dialog__item--wide { grid-column: auto; } }
    `;
    document.head.appendChild(style);

    alertDialog = document.createElement("dialog");
    alertDialog.className = "alert-detail-dialog";
    alertDialog.setAttribute("aria-labelledby", "alert-detail-title");
    alertDialog.innerHTML = `
      <div class="alert-detail-dialog__content">
        <div class="alert-detail-dialog__header">
          <div>
            <p class="eyebrow">SURVEILLANCE</p>
            <h2 id="alert-detail-title">Détail de l’alerte</h2>
          </div>
          <button class="refresh-button alert-detail-dialog__close" type="button" aria-label="Fermer">×</button>
        </div>
        <div class="alert-detail-dialog__grid" data-alert-detail-grid></div>
      </div>
    `;
    document.body.appendChild(alertDialog);

    alertDialog.querySelector(".alert-detail-dialog__close").addEventListener(
      "click",
      () => alertDialog.close()
    );
    alertDialog.addEventListener("click", (event) => {
      if (event.target === alertDialog) alertDialog.close();
    });

    return alertDialog;
  }

  function showAlertDetails(alert) {
    const dialog = ensureAlertDialog();
    const grid = dialog.querySelector("[data-alert-detail-grid]");
    const labels = {
      timestamp: "Heure",
      created_at: "Heure",
      detected_at: "Heure",
      severity: "Niveau",
      level: "Niveau",
      priority: "Priorité",
      title: "Détection",
      description: "Description",
      message: "Détail",
      detection: "Détection",
      rule_name: "Règle",
      rule_id: "Identifiant de règle",
      source_ip: "Adresse source",
      source: "Source",
      source_address: "Adresse source",
      destination_ip: "Adresse cible",
      target_ip: "Adresse cible",
      destination: "Cible",
      target: "Cible",
      protocol: "Protocole",
      status: "État",
      state: "État",
      packet_count: "Paquets concernés",
      threshold: "Seuil",
      evidence: "Éléments observés",
    };
    const preferred = Object.keys(labels);
    const keys = [
      ...preferred.filter((key) => alert[key] !== undefined && alert[key] !== null),
      ...Object.keys(alert).filter((key) => !preferred.includes(key)),
    ];
    const seen = new Set();
    grid.replaceChildren();

    for (const key of keys) {
      const value = alert[key];
      if (value === undefined || value === null || seen.has(key)) continue;
      seen.add(key);

      const item = document.createElement("div");
      item.className = "alert-detail-dialog__item";
      if (["description", "message", "detection", "evidence"].includes(key)) {
        item.classList.add("alert-detail-dialog__item--wide");
      }

      const label = document.createElement("span");
      label.className = "alert-detail-dialog__label";
      label.textContent = labels[key] || key.replaceAll("_", " ");

      const content = document.createElement("div");
      content.className = "alert-detail-dialog__value";
      content.textContent = Array.isArray(value)
        ? value.join(", ")
        : typeof value === "object"
          ? JSON.stringify(value, null, 2)
          : String(value);
      if (["timestamp", "created_at", "detected_at"].includes(key)) {
        content.textContent = formatDateTime(value);
      }

      item.append(label, content);
      grid.appendChild(item);
    }

    if (typeof dialog.showModal === "function") dialog.showModal();
    else dialog.setAttribute("open", "");
  }

  function displayAlerts(alerts) {
    if (alertsValue) {
      alertsValue.textContent = formatNumber(alerts.length);
    }

    if (!alertsBody) return;

    if (alerts.length === 0) {
      setEmptyRow(alertsBody, 6, "Aucune alerte détectée dans cette session.");
      return;
    }

    alertsBody.replaceChildren();

    for (const alert of alerts) {
      const row = document.createElement("tr");
      row.dataset.alertRow = "true";
      row.tabIndex = 0;
      row.setAttribute("role", "button");
      row.setAttribute("aria-label", "Afficher le détail de cette alerte");
      row.addEventListener("click", () => showAlertDetails(alert));
      row.addEventListener("keydown", (event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          showAlertDetails(alert);
        }
      });

      const source =
        alert.source_ip || alert.source || alert.source_address || "—";
      const target =
        alert.destination_ip ||
        alert.target ||
        alert.destination ||
        alert.target_ip ||
        "—";
      const detection =
        alert.description ||
        alert.message ||
        alert.detection ||
        alert.rule_name ||
        "Activité à examiner";
      const severity =
        alert.severity || alert.level || alert.priority || "Information";
      const state = alert.status || alert.state || "À examiner";

      addCell(
        row,
        formatTime(alert.timestamp || alert.created_at || alert.detected_at)
      );
      addCell(row, severity);
      addCell(row, detection);
      addCell(row, source, "address-cell");
      addCell(row, target, "address-cell");
      addCell(row, state);

      alertsBody.appendChild(row);
    }
  }

  function ensureHistoryExportHeader() {
    const headerRow = historyBody
      ?.closest("table")
      ?.querySelector("thead tr");

    if (!headerRow) return;

    const actionHeader = Array.from(headerRow.cells).find(
      (cell) => cell.dataset.historyExportHeader === "true"
    );

    if (actionHeader) {
      actionHeader.textContent = "ACTIONS";
      return;
    }

    const header = document.createElement("th");
    header.textContent = "ACTIONS";
    header.dataset.historyExportHeader = "true";
    header.scope = "col";
    headerRow.appendChild(header);
  }

  function parseSemicolonCsv(text) {
    const rows = [];
    let row = [];
    let cell = "";
    let quoted = false;
    const source = String(text || "").replace(/^\uFEFF/, "");

    for (let index = 0; index < source.length; index += 1) {
      const character = source[index];

      if (quoted) {
        if (character === '"' && source[index + 1] === '"') {
          cell += '"';
          index += 1;
        } else if (character === '"') {
          quoted = false;
        } else {
          cell += character;
        }
      } else if (character === '"') {
        quoted = true;
      } else if (character === ";") {
        row.push(cell);
        cell = "";
      } else if (character === "\n") {
        row.push(cell.replace(/\r$/, ""));
        if (row.some((value) => value !== "")) rows.push(row);
        row = [];
        cell = "";
      } else {
        cell += character;
      }
    }

    if (cell !== "" || row.length > 0) {
      row.push(cell.replace(/\r$/, ""));
      if (row.some((value) => value !== "")) rows.push(row);
    }

    if (rows.length < 2) return [];

    const headers = rows[0].map((value) => value.trim().toLowerCase());
    const indexOf = (...names) => headers.findIndex((header) => names.includes(header));
    const columns = {
      timestamp: indexOf("horodatage", "timestamp"),
      source: indexOf("adresse source", "source"),
      sourcePort: indexOf("port source", "source port"),
      destination: indexOf("adresse destination", "destination"),
      destinationPort: indexOf("port destination", "destination port"),
      protocol: indexOf("protocole", "protocol"),
      transport: indexOf("protocole transport", "transport protocol"),
      application: indexOf("protocole application", "application protocol"),
      flags: indexOf("indicateurs tcp", "tcp flags"),
      size: indexOf("taille en octets", "packet length bytes", "taille"),
    };

    return rows.slice(1).map((values) => {
      const get = (key) => columns[key] >= 0 ? values[columns[key]] || "" : "";
      return {
        timestamp: get("timestamp"),
        source_ip: get("source"),
        source_port: get("sourcePort"),
        destination_ip: get("destination"),
        destination_port: get("destinationPort"),
        protocol: get("protocol"),
        transport_protocol: get("transport"),
        application_protocol: get("application"),
        tcp_flags: get("flags"),
        packet_length_bytes: get("size"),
      };
    });
  }

  function getArchiveProtocol(packet) {
    const unknownValues = new Set([
      "", "INCONNU", "NON IDENTIFIÉ", "NON IDENTIFIE", "UNKNOWN",
    ]);
    const candidates = [
      packet.application_protocol,
      packet.transport_protocol,
      packet.protocol,
    ];
    const known = candidates.find((value) =>
      !unknownValues.has(String(value || "").trim().toUpperCase())
    );

    if (known) return String(known).trim().toUpperCase();
    if (packet.tcp_flags && packet.tcp_flags !== "—") return "TCP";

    const ports = [packet.source_port, packet.destination_port].map(Number);
    if (ports.some((port) => [53, 5353].includes(port))) return "DNS";
    if (ports.some((port) => [67, 68].includes(port))) return "DHCP";
    if (ports.includes(1900)) return "SSDP";
    return "Non identifié";
  }

  function ensureArchiveDialog() {
    if (archiveDialog) return archiveDialog;

    const style = document.createElement("style");
    style.textContent = `
      .archive-dialog {
        width: min(1100px, calc(100vw - 28px));
        max-height: min(88vh, 900px);
        padding: 0;
        color: #e5edf3;
        background: #08131e;
        border: 1px solid rgba(145, 170, 188, .28);
        border-radius: 16px;
        box-shadow: 0 24px 80px rgba(0, 0, 0, .6);
      }
      .archive-dialog::backdrop { background: rgba(1, 7, 12, .8); backdrop-filter: blur(4px); }
      .archive-dialog__content { padding: 22px; }
      .archive-dialog__header { display: flex; justify-content: space-between; gap: 16px; align-items: start; }
      .archive-dialog__header h2 { margin: 4px 0 18px; }
      .archive-dialog__controls { display: grid; grid-template-columns: minmax(180px, 1fr) minmax(160px, 240px); gap: 12px; margin: 12px 0; }
      .archive-dialog__controls input, .archive-dialog__controls select { width: 100%; min-height: 44px; padding: 9px 12px; color: inherit; background: #0b1924; border: 1px solid rgba(145, 170, 188, .28); border-radius: 10px; }
      .archive-dialog__table { max-height: 55vh; overflow: auto; scroll-behavior: auto; }
      .archive-dialog__table thead th { position: sticky; top: 0; z-index: 2; background: #08131e; }
      .archive-dialog__close { min-width: 40px; min-height: 40px; cursor: pointer; }
      .archive-dialog__more { margin: 12px 0; }
      @media (max-width: 620px) { .archive-dialog__content { padding: 14px; } .archive-dialog__controls { grid-template-columns: 1fr; } }
    `;
    document.head.appendChild(style);

    archiveDialog = document.createElement("dialog");
    archiveDialog.className = "archive-dialog";
    archiveDialog.setAttribute("aria-labelledby", "archive-dialog-title");
    archiveDialog.innerHTML = `
      <div class="archive-dialog__content">
        <div class="archive-dialog__header">
          <div>
            <p class="eyebrow">ARCHIVES</p>
            <h2 id="archive-dialog-title">Paquets de la capture</h2>
          </div>
          <button class="refresh-button archive-dialog__close" type="button" aria-label="Fermer">×</button>
        </div>
        <div class="archive-dialog__controls">
          <input type="search" data-archive-search placeholder="Rechercher une adresse, un port ou un indicateur…" aria-label="Rechercher dans les paquets archivés">
          <select data-archive-protocol aria-label="Filtrer les paquets par protocole"><option value="">Tous les protocoles</option></select>
        </div>
        <p data-archive-count role="status" aria-live="polite">Chargement des paquets…</p>
        <div class="table-wrap archive-dialog__table">
          <table class="packet-table" aria-label="Paquets archivés">
            <thead><tr><th>HEURE</th><th>SOURCE</th><th>DESTINATION</th><th>PROTOCOLE</th><th>INDICATEURS TCP</th><th>TAILLE</th></tr></thead>
            <tbody data-archive-body><tr><td colspan="6" class="table-empty">Chargement des paquets…</td></tr></tbody>
          </table>
        </div>
        <button class="refresh-button archive-dialog__more" data-archive-more type="button" hidden>Afficher plus</button>
      </div>
    `;
    document.body.appendChild(archiveDialog);

    const closeButton = archiveDialog.querySelector(".archive-dialog__close");
    closeButton.addEventListener("click", () => archiveDialog.close());
    archiveDialog.addEventListener("click", (event) => {
      if (event.target === archiveDialog) archiveDialog.close();
    });

    return archiveDialog;
  }

  function renderArchivePackets(packets, errorText = "") {
    if (!archiveDialog) return;

    const body = archiveDialog.querySelector("[data-archive-body]");
    const count = archiveDialog.querySelector("[data-archive-count]");
    const search = archiveDialog.querySelector("[data-archive-search]");
    const protocolSelect = archiveDialog.querySelector("[data-archive-protocol]");
    const moreButton = archiveDialog.querySelector("[data-archive-more]");
    const searchTerm = search.value.trim().toLowerCase();
    const protocol = protocolSelect.value.toUpperCase();

    const visible = packets.filter((packet) => {
      const protocolValues = [packet.protocol, packet.transport_protocol, packet.application_protocol]
        .map(normalizeProtocol);
      if (protocol && !protocolValues.includes(protocol)) return false;
      const haystack = [packet.source_ip, packet.source_port, packet.destination_ip,
        packet.destination_port, packet.protocol, packet.transport_protocol,
        packet.application_protocol, packet.tcp_flags, packet.timestamp,
        packet.packet_length_bytes].join(" ").toLowerCase();
      return !searchTerm || haystack.includes(searchTerm);
    });

    const shownCount = Math.min(archiveShownCount, visible.length);
    count.textContent = errorText || `${formatNumber(shownCount)} paquet(s) affiché(s) sur ${formatNumber(visible.length)} résultat(s), ${formatNumber(packets.length)} archivé(s).`;
    body.replaceChildren();

    if (errorText || visible.length === 0) {
      setEmptyRow(body, 6, errorText || "Aucun paquet ne correspond aux filtres.");
      moreButton.hidden = true;
      return;
    }

    const pageSize = 100;
    for (const packet of visible.slice(0, shownCount)) {
      const row = document.createElement("tr");
      addCell(row, formatTime(packet.timestamp));
      addCell(row, formatEndpoint(packet.source_ip, packet.source_port), "address-cell");
      addCell(row, formatEndpoint(packet.destination_ip, packet.destination_port), "address-cell");
      addCell(row, getArchiveProtocol(packet), "protocol-cell");
      addCell(row, packet.tcp_flags || "—");
      addCell(row, formatBytes(Number(packet.packet_length_bytes || 0)));
      body.appendChild(row);
    }

    moreButton.hidden = shownCount >= visible.length;
    moreButton.textContent = `Afficher ${formatNumber(Math.min(pageSize, visible.length - shownCount))} paquet(s) supplémentaire(s)`;
    moreButton.onclick = () => {
      archiveShownCount = Math.min(archiveShownCount + pageSize, visible.length);
      renderArchivePackets(packets);
    };
  }

  async function showArchivedPackets(sessionId) {
    const dialog = ensureArchiveDialog();
    const body = dialog.querySelector("[data-archive-body]");
    const count = dialog.querySelector("[data-archive-count]");
    const search = dialog.querySelector("[data-archive-search]");
    const protocolSelect = dialog.querySelector("[data-archive-protocol]");
    const moreButton = dialog.querySelector("[data-archive-more]");

    dialog.dataset.sessionId = String(sessionId);
    archiveShownCount = 100;
    dialog.scrollTop = 0;
    dialog.querySelector(".archive-dialog__table").scrollTop = 0;
    search.value = "";
    protocolSelect.replaceChildren(new Option("Tous les protocoles", ""));
    moreButton.hidden = true;
    count.textContent = "Chargement des paquets…";
    setEmptyRow(body, 6, "Chargement des paquets…");
    if (typeof dialog.showModal === "function") dialog.showModal();
    else dialog.setAttribute("open", "");

    try {
      const response = await fetch(`/api/history/${encodeURIComponent(sessionId)}/packets.csv`);
      if (!response.ok) throw new Error(`Erreur ${response.status} pendant le chargement.`);
      const packets = parseSemicolonCsv(await response.text());
      const protocols = [...new Set(packets.map((packet) =>
        getArchiveProtocol(packet).toUpperCase()
      ))].sort();
      for (const value of protocols) protocolSelect.add(new Option(value, value));

      search.oninput = () => {
        archiveShownCount = 100;
        dialog.querySelector(".archive-dialog__table").scrollTop = 0;
        renderArchivePackets(packets);
      };
      protocolSelect.onchange = () => {
        archiveShownCount = 100;
        dialog.querySelector(".archive-dialog__table").scrollTop = 0;
        renderArchivePackets(packets);
      };
      renderArchivePackets(packets);
      dialog.scrollTop = 0;
      dialog.querySelector(".archive-dialog__table").scrollTop = 0;
    } catch (error) {
      count.textContent = "Impossible de charger les paquets archivés.";
      setEmptyRow(body, 6, error.message || "Vérifie que la capture possède un export CSV.");
    }
  }

  function displayHistory(sessions) {
    if (!historyBody) return;

    ensureHistoryExportHeader();

    if (sessions.length === 0) {
      setEmptyRow(historyBody, 7, "Aucune session enregistrée.");
      return;
    }

    const statusLabels = {
      RUNNING: "En cours",
      STOPPED: "Arrêtée",
      INTERRUPTED: "Interrompue",
      ERROR: "Erreur",
    };

    historyBody.replaceChildren();

    for (const session of sessions) {
      const row = document.createElement("tr");

      addCell(row, formatDateTime(session.started_at));
      addCell(
        row,
        session.interface_name || session.interface_id || "—",
        "address-cell"
      );
      addCell(
        row,
        statusLabels[session.status] || session.status || "—"
      );
      addCell(row, formatNumber(session.packet_count));
      addCell(row, formatBytes(session.bytes_captured));
      addCell(row, formatDateTime(session.ended_at));

      const actionCell = document.createElement("td");
      const sessionId = Number(session.id);

      if (Number.isInteger(sessionId) && sessionId > 0) {
        const viewButton = document.createElement("button");
        viewButton.className = "refresh-button history-export-link";
        viewButton.type = "button";
        viewButton.textContent = "Voir";
        viewButton.setAttribute("aria-label", `Afficher les paquets de la session ${sessionId}`);
        viewButton.addEventListener("click", () => showArchivedPackets(sessionId));
        actionCell.appendChild(viewButton);

        const exportLink = document.createElement("a");
        exportLink.className = "refresh-button history-export-link";
        exportLink.textContent = "CSV";
        exportLink.href =
          `/api/history/${encodeURIComponent(sessionId)}/packets.csv`;
        exportLink.setAttribute(
          "aria-label",
          `Télécharger les paquets de la session ${sessionId} en CSV`
        );

        actionCell.appendChild(exportLink);
      } else {
        actionCell.textContent = "—";
      }

      row.appendChild(actionCell);
      historyBody.appendChild(row);
    }
  }

  function drawTrafficChart() {
    if (!trafficChart) return;

    const context = trafficChart.getContext("2d");
    if (!context) return;

    const bounds = trafficChart.getBoundingClientRect();
    const pixelRatio = window.devicePixelRatio || 1;
    const width = Math.max(bounds.width, 300);
    const height = Math.max(bounds.height, 180);

    trafficChart.width = Math.round(width * pixelRatio);
    trafficChart.height = Math.round(height * pixelRatio);

    context.scale(pixelRatio, pixelRatio);
    context.clearRect(0, 0, width, height);

    const padding = { top: 16, right: 12, bottom: 12, left: 12 };
    const chartWidth = width - padding.left - padding.right;
    const chartHeight = height - padding.top - padding.bottom;

    context.strokeStyle = "rgba(145, 170, 188, 0.18)";
    context.lineWidth = 1;

    for (let index = 0; index < 4; index += 1) {
      const y = padding.top + (chartHeight * index) / 3;

      context.beginPath();
      context.moveTo(padding.left, y);
      context.lineTo(width - padding.right, y);
      context.stroke();
    }

    if (chartHistory.length < 2) return;

    const maximum = Math.max(...chartHistory, 1);
    const points = chartHistory.map((value, index) => ({
      x: padding.left + (chartWidth * index) / (chartHistory.length - 1),
      y: padding.top + chartHeight - (value / maximum) * chartHeight,
    }));

    const gradient = context.createLinearGradient(
      0,
      padding.top,
      0,
      height - padding.bottom
    );

    gradient.addColorStop(0, "rgba(72, 214, 229, 0.24)");
    gradient.addColorStop(1, "rgba(72, 214, 229, 0.01)");

    context.beginPath();
    context.moveTo(points[0].x, height - padding.bottom);

    for (const point of points) {
      context.lineTo(point.x, point.y);
    }

    context.lineTo(
      points[points.length - 1].x,
      height - padding.bottom
    );

    context.closePath();
    context.fillStyle = gradient;
    context.fill();

    context.beginPath();
    context.moveTo(points[0].x, points[0].y);

    for (const point of points.slice(1)) {
      context.lineTo(point.x, point.y);
    }

    context.strokeStyle = "#48d6e5";
    context.lineWidth = 3;
    context.lineJoin = "round";
    context.lineCap = "round";
    context.shadowColor = "rgba(72, 214, 229, 0.35)";
    context.shadowBlur = 8;
    context.stroke();
    context.shadowBlur = 0;

    const lastPoint = points[points.length - 1];

    context.beginPath();
    context.arc(lastPoint.x, lastPoint.y, 4, 0, Math.PI * 2);
    context.fillStyle = "#72e5ee";
    context.fill();
  }

  function updateTrafficChart(status) {
    const currentBytes = Number(status.bytes_captured || 0);
    let bytesPerSecond = 0;

    if (previousBytes !== null) {
      bytesPerSecond = Math.max(0, currentBytes - previousBytes);
    }

    previousBytes = currentBytes;
    chartHistory.push(bytesPerSecond);

    if (chartHistory.length > maxChartPoints) {
      chartHistory.shift();
    }

    if (trafficRate) {
      trafficRate.textContent = `${formatBytes(bytesPerSecond)}/s`;
    }

    if (trafficChartMessage) {
      trafficChartMessage.textContent =
        status.status === "RUNNING"
          ? "Débit mesuré pendant la capture."
          : "Le débit apparaîtra pendant une capture.";
    }

    drawTrafficChart();
  }

  function updateButtons() {
    const isBusy = ["STARTING", "RUNNING", "STOPPING"].includes(
      lastStatus.status
    );

    select.disabled = isBusy || select.options.length <= 1;
    refreshButton.disabled = isBusy;
    startButton.disabled = isBusy || !select.value;
    stopButton.disabled = lastStatus.status !== "RUNNING";
  }

  function updateStatus(data) {
    lastStatus = data;

    const labels = {
      IDLE: "Capture inactive",
      STARTING: "Démarrage de la capture…",
      RUNNING: "Capture en cours",
      STOPPING: "Arrêt de la capture…",
      STOPPED: "Capture arrêtée",
      ERROR: "Erreur de capture",
    };

    if (captureState) {
      captureState.textContent = labels[data.status] || "État inconnu";
    }

    if (captureInterface) {
      captureInterface.textContent =
        data.interface_name || "Aucune interface sélectionnée";
    }

    if (captureDot) {
      captureDot.classList.toggle(
        "status-dot--running",
        data.status === "RUNNING"
      );
    }

    if (packetsValue) {
      packetsValue.textContent = formatNumber(data.packet_count);
    }

    if (trafficValue) {
      trafficValue.textContent = formatBytes(data.bytes_captured);
    }

    if (data.message && message) {
      message.textContent = data.message;
    }

    if (data.interface_id) {
      const matchingOption = Array.from(select.options).find(
        (option) => option.value === data.interface_id
      );

      if (matchingOption) {
        select.value = data.interface_id;
      }
    }

    updateTrafficChart(data);
    updateButtons();

    const isActive = ["STARTING", "RUNNING", "STOPPING"].includes(
      data.status
    );

    if (isActive && statusTimer === null) {
      statusTimer = window.setInterval(() => {
        refreshStatus();
        refreshPackets();
        refreshFlows();
        refreshAlerts();
        refreshHistory();
      }, 1000);
    } else if (!isActive && statusTimer !== null) {
      window.clearInterval(statusTimer);
      statusTimer = null;
    }
  }

  async function refreshStatus() {
    try {
      const data = await requestJson("/api/capture/status");
      updateStatus(data);
    } catch (error) {
      if (message) message.textContent = error.message;
    }
  }

  async function refreshPackets() {
    try {
      const data = await requestJson("/api/packets?limit=50");
      latestPackets = Array.isArray(data.packets) ? data.packets : [];

      updateProtocolSelect(
        packetProtocol,
        latestPackets.flatMap((packet) => [
          packet.protocol,
          packet.transport_protocol,
          packet.application_protocol,
        ]),
        "Tous les protocoles"
      );

      displayPackets();
    } catch (error) {
      latestPackets = [];
      displayPackets();

      if (message) {
        message.textContent =
          `Impossible de charger les paquets : ${error.message}`;
      }
    }
  }

  async function refreshFlows() {
    try {
      const data = await requestJson("/api/flows?limit=500");
      latestFlows = Array.isArray(data.flows) ? data.flows : [];

      updateProtocolSelect(
        flowProtocol,
        latestFlows.map((flow) => flow.protocol),
        "Tous les protocoles"
      );

      displayProtocols(latestFlows);
      displayFlows();
    } catch (error) {
      latestFlows = [];
      displayProtocols([]);
      displayFlows();

      if (message) {
        message.textContent =
          `Impossible de charger les communications : ${error.message}`;
      }
    }
  }

  async function refreshAlerts() {
    try {
      const data = await requestJson("/api/alerts?limit=100");
      displayAlerts(Array.isArray(data.alerts) ? data.alerts : []);
    } catch (error) {
      displayAlerts([]);

      if (message) {
        message.textContent =
          `Impossible de charger les alertes : ${error.message}`;
      }
    }
  }

  async function refreshHistory() {
    try {
      const data = await requestJson("/api/history?limit=50");
      displayHistory(Array.isArray(data.sessions) ? data.sessions : []);
    } catch (error) {
      if (historyBody) {
        ensureHistoryExportHeader();
        setEmptyRow(
          historyBody,
          7,
          `Impossible de charger l’historique : ${error.message}`
        );
      }
    }
  }

  async function loadInterfaces() {
    select.disabled = true;
    select.replaceChildren(new Option("Chargement des interfaces…", ""));

    if (message) {
      message.textContent = "Recherche des interfaces réseau…";
    }

    try {
      const data = await requestJson("/api/interfaces");
      const interfaces = Array.isArray(data.interfaces)
        ? data.interfaces
        : [];

      select.replaceChildren(new Option("Choisir une interface…", ""));

      for (const networkInterface of interfaces) {
        const address =
          networkInterface.ipv4 &&
          networkInterface.ipv4 !== "Non disponible"
            ? networkInterface.ipv4
            : "adresse IP indisponible";

        select.add(
          new Option(
            `${networkInterface.name} — ${address}`,
            networkInterface.id
          )
        );
      }

      if (interfaces.length === 0 && message) {
        message.textContent =
          data.message || "Aucune interface n’a été détectée.";
      } else if (message) {
        message.textContent =
          `${interfaces.length} interface(s) détectée(s). ` +
          "Choisis-en une pour démarrer.";
      }

      await refreshStatus();
      await refreshPackets();
      await refreshFlows();
      await refreshAlerts();
      await refreshHistory();

      updateButtons();
    } catch (error) {
      select.replaceChildren(new Option("Interfaces indisponibles", ""));

      if (message) {
        message.textContent = error.message;
      }

      updateButtons();
    }
  }

  function clearPacketFiltersHandler() {
    if (packetSearch) packetSearch.value = "";
    if (packetProtocol) packetProtocol.value = "";

    displayPackets();
    packetSearch?.focus();
  }

  function clearFlowFiltersHandler() {
    if (flowSearch) flowSearch.value = "";
    if (flowProtocol) flowProtocol.value = "";

    displayFlows();
    flowSearch?.focus();
  }

  function handleFlowHeaderClick(event) {
    const header = event.target.closest("th");
    if (!header) return;

    const headers = Array.from(header.parentElement.children);
    const columnIndex = headers.indexOf(header);

    const sortKeys = [
      "last_seen",
      "endpoint_a",
      "endpoint_b",
      "protocol",
      "packet_count",
      "bytes_total",
    ];

    const selectedKey = sortKeys[columnIndex];
    if (!selectedKey) return;

    if (flowSort.key === selectedKey) {
      flowSort.direction =
        flowSort.direction === "asc" ? "desc" : "asc";
    } else {
      flowSort.key = selectedKey;
      flowSort.direction =
        selectedKey === "last_seen" ? "desc" : "asc";
    }

    displayFlows();
  }

  select.addEventListener("change", updateButtons);
  refreshButton.addEventListener("click", loadInterfaces);

  packetSearch?.addEventListener("input", displayPackets);
  packetProtocol?.addEventListener("change", displayPackets);

  clearPacketFilters?.addEventListener(
    "click",
    clearPacketFiltersHandler
  );

  exportPacketsButton?.addEventListener(
    "click",
    exportVisiblePackets
  );

  flowSearch?.addEventListener("input", displayFlows);
  flowProtocol?.addEventListener("change", displayFlows);

  clearFlowFilters?.addEventListener(
    "click",
    clearFlowFiltersHandler
  );

  exportFlowsButton?.addEventListener(
    "click",
    exportVisibleFlows
  );

  document
    .querySelector(".flow-table thead")
    ?.addEventListener("click", handleFlowHeaderClick);

  startButton.addEventListener("click", async () => {
    if (!select.value) {
      if (message) {
        message.textContent = "Choisis d’abord une interface réseau.";
      }
      return;
    }

    startButton.disabled = true;

    if (message) {
      message.textContent = "Demande de démarrage…";
    }

    try {
      const data = await requestJson("/api/capture/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ interface_id: select.value }),
      });

      chartHistory.length = 0;
      previousBytes = null;
      updateStatus(data);

      await refreshPackets();
      await refreshFlows();
      await refreshAlerts();
      await refreshHistory();
    } catch (error) {
      if (message) message.textContent = error.message;
      await refreshStatus();
    }
  });

  stopButton.addEventListener("click", async () => {
    stopButton.disabled = true;

    if (message) {
      message.textContent = "Demande d’arrêt…";
    }

    try {
      const data = await requestJson("/api/capture/stop", {
        method: "POST",
      });

      updateStatus(data);

      await refreshPackets();
      await refreshFlows();
      await refreshAlerts();
      await refreshHistory();
    } catch (error) {
      if (message) message.textContent = error.message;
      await refreshStatus();
    }
  });

  window.addEventListener("resize", drawTrafficChart);

  loadInterfaces();
});
