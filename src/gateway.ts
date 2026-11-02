import type { WebSocket } from "undici";


type Socket = Pick<InstanceType<typeof WebSocket>, "send" | "close" | "addEventListener">;
type GatewayOptions = { applicationId: string; directed?: boolean; guildMessageContent?: boolean; identifyLimit?: number; interaction?: (value: unknown) => Promise<void>; factory: (url: string) => Socket };
export function gatewayUrl(raw: string): string {
  const url = new URL(raw);
  if (url.protocol !== "wss:" || url.hostname !== "gateway.discord.gg" || url.username || url.password || url.port || url.hash) throw new Error("Gateway URL denied");
  url.search = "?v=10&encoding=json";
  return url.toString();
}

/** Gateway protocol only; socket construction is owned by the standalone network adapter.
 * Reconnect creates a fresh session: this connector never requests a historical Gateway replay.
 */
export class DiscordGateway {
  private socket?: Socket;
  private heartbeat?: ReturnType<typeof setInterval>;
  private firstBeat?: ReturnType<typeof setTimeout>;
  private helloDeadline?: ReturnType<typeof setTimeout>;
  private reconnect?: ReturnType<typeof setTimeout>;
  private seq: number | null = null;
  private ack = true;
  private stopped = false;
  private attempts = 0;
  private pending = 0;
  private identifies = 0;
  private helloReceived = false;
  ready = false;
  constructor(
    private readonly token: string, private readonly botId: string, private readonly url: string,
    private readonly ingest: (message: unknown) => Promise<unknown>, private readonly log: (code: string) => void,
    private readonly options: GatewayOptions
  ) {}
  start() {
    if (this.stopped) return;
    const socket = this.options.factory(gatewayUrl(this.url));
    this.socket = socket;
    this.seq = null;
    this.helloReceived = false;
    this.helloDeadline = setTimeout(() => socket.close(4000), 15_000);
    socket.addEventListener("message", (event) => {
      if (socket !== this.socket || this.stopped) return;
      try {
        if (typeof event.data !== "string" || Buffer.byteLength(event.data) > 262_144) throw new Error();
        this.packet(JSON.parse(event.data));
      } catch { this.log("gateway_packet_rejected"); socket.close(4000); }
    });
    socket.addEventListener("error", () => { this.log("gateway_transport_error"); socket.close(4000); });
    socket.addEventListener("close", (event) => {
      if (socket !== this.socket) return;
      this.ready = false;
      this.clearHeartbeat();
      if (this.stopped) return;
      if ([4004, 4010, 4011, 4012, 4013, 4014].includes(event.code) || ++this.attempts > 8) { this.stop(); this.log("gateway_stopped"); return; }
      this.reconnect = setTimeout(() => this.start(), Math.min(60_000, 1000 * 2 ** this.attempts) + Math.random() * 1000);
    });
  }
  private emit(op: number, d: unknown) {
    try { this.socket?.send(JSON.stringify({ op, d })); } catch { this.socket?.close(4000); }
  }
  private beat() {
    if (!this.ack) { this.socket?.close(4000); return; }
    this.ack = false; this.emit(1, this.seq);
  }
  private packet(packet: { op: number; s?: number; t?: string; d?: unknown }) {
    if (!packet || typeof packet !== "object" || !Number.isInteger(packet.op)) throw new Error();
    if (Number.isSafeInteger(packet.s)) this.seq = packet.s!;
    if (packet.op === 10) {
      if (this.helloReceived) throw new Error("duplicate Gateway hello");
      this.helloReceived = true;
      if (++this.identifies > (this.options.identifyLimit ?? 8)) { this.stop(); this.log("gateway_session_budget_exhausted"); return; }
      clearTimeout(this.helloDeadline);
      const interval = (packet.d as { heartbeat_interval?: unknown })?.heartbeat_interval;
      if (typeof interval !== "number" || !Number.isFinite(interval) || interval < 1000 || interval > 120_000) throw new Error();
      this.clearHeartbeat(); this.ack = true;
      this.firstBeat = setTimeout(() => { this.beat(); this.heartbeat = setInterval(() => this.beat(), interval); }, Math.random() * interval);
      // Guild events and privileged content each require an explicit operator opt-in.
      const intents = this.options.directed ? 4608 | (this.options.guildMessageContent ? 32768 : 0) : 4096;
      this.emit(2, {
        token: this.token, intents, properties: { os: process.platform, browser: "dotcord", device: "dotcord" },
        presence: { status: "idle", since: null, afk: false, activities: [{ name: "Custom Status", type: 4, state: "" }] }
      });
    } else if (packet.op === 11) this.ack = true;
    else if (packet.op === 1) this.emit(1, this.seq);
    else if ([7, 9].includes(packet.op)) this.socket?.close(4000);
    else if (packet.op === 0 && packet.t === "READY") {
      const data = packet.d as { user?: { id?: string; bot?: boolean }; application?: { id?: string } };
      if (!this.helloReceived || data?.user?.id !== this.botId || data.user.bot !== true || data.application?.id !== this.options.applicationId) { this.stop(); this.log("gateway_identity_mismatch"); return; }
      this.ready = true; this.attempts = 0; this.log("gateway_ready");
    } else if (packet.op === 0 && packet.t === "INTERACTION_CREATE" && this.ready && this.options.interaction) {
      if (this.pending >= 100) { this.log("gateway_capacity_reached"); return; }
      this.pending++;
      void this.options.interaction(packet.d).catch(() => this.log("interaction_failed")).finally(() => { this.pending--; });
    } else if (packet.op === 0 && packet.t === "MESSAGE_CREATE" && this.ready) {
      if (this.pending >= 100) { this.log("gateway_capacity_reached"); return; }
      this.pending++;
      void this.ingest(packet.d).catch(() => this.log("ingest_failed")).finally(() => { this.pending--; });
    }
  }
  private clearHeartbeat() { clearInterval(this.heartbeat); clearTimeout(this.firstBeat); clearTimeout(this.helloDeadline); }
  stop() {
    this.stopped = true; this.ready = false;
    this.clearHeartbeat(); clearTimeout(this.reconnect); this.socket?.close(1000);
  }
}
