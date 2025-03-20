// Deno-specific imports
import { serve } from "https://deno.land/std/http/server.ts";

// Environment variables with TypeScript typing
const UUID: string = Deno.env.get("UUID") || "0cf85927-2c71-4e87-9df3-b1eb7d5a9e1b";
const AUTO_ACCESS: boolean = Deno.env.get("AUTO_ACCESS") === "true";
const SUB_PATH: string = Deno.env.get("SUB_PATH") || "sub";
const XPATH: string = Deno.env.get("XPATH") || "xhttp";
const DOMAIN: string = Deno.env.get("DOMAIN") || "";
const NAME: string = Deno.env.get("NAME") || "Vls";
const PORT: number = parseInt(Deno.env.get("PORT") || "3000");

// Core configuration with TypeScript interface
interface Settings {
  UUID: string;
  LOG_LEVEL: "none" | "debug" | "info" | "warn" | "error";
  BUFFER_SIZE: number;
  XPATH: string;
  MAX_BUFFERED_POSTS: number;
  MAX_POST_SIZE: number;
  SESSION_TIMEOUT: number;
  CHUNK_SIZE: number;
  TCP_NODELAY: boolean;
  TCP_KEEPALIVE: boolean;
}

const SETTINGS: Settings = {
  UUID,
  LOG_LEVEL: "none",
  BUFFER_SIZE: 2048,
  XPATH: `%2F${XPATH}`,
  MAX_BUFFERED_POSTS: 100,
  MAX_POST_SIZE: 3000000,
  SESSION_TIMEOUT: 30000,
  CHUNK_SIZE: 1024 * 1024,
  TCP_NODELAY: true,
  TCP_KEEPALIVE: true,
};

// Utility functions
function validate_uuid(left: Uint8Array, right: Uint8Array): boolean {
  for (let i = 0; i < 16; i++) {
    if (left[i] !== right[i]) return false;
  }
  return true;
}

function concat_typed_arrays(...args: Uint8Array[]): Uint8Array {
  let len = 0;
  for (const a of args) len += a.length;
  const r = new Uint8Array(len);
  let offset = 0;
  for (const a of args) {
    r.set(a, offset);
    offset += a.length;
  }
  return r;
}

// Logging function
function log(type: "debug" | "info" | "warn" | "error", ...args: any[]): void {
  if (SETTINGS.LOG_LEVEL === "none") return;

  const levels: Record<string, number> = {
    debug: 0,
    info: 1,
    warn: 2,
    error: 3,
  };

  const configLevel = levels[SETTINGS.LOG_LEVEL] || 1;
  const messageLevel = levels[type] || 0;

  if (messageLevel >= configLevel) {
    const time = new Date().toISOString();
    console.log(`[${time}] [${type}]`, ...args);
  }
}

// Automatic access task
async function addAccessTask(): Promise<void> {
  if (!AUTO_ACCESS) return;
  try {
    if (!DOMAIN) {
      console.log("URL is empty. Skip Adding Automatic Access Task");
      return;
    }
    const fullURL = `https://${DOMAIN}`;
    const command = `curl -X POST "https://oooo.serv00.net/add-url" -H "Content-Type: application/json" -d '{"url": "${fullURL}"}'`;
    const p = Deno.run({
      cmd: ["sh", "-c", command],
      stdout: "piped",
      stderr: "piped",
    });
    const output = await p.output();
    const stdout = new TextDecoder().decode(output);
    console.log("Automatic Access Task added successfully:", stdout);
  } catch (error) {
    console.error("Error added Task:", error.message);
  }
}

// VLESS protocol parsing
function parse_uuid(uuid: string): Uint8Array {
  uuid = uuid.replaceAll("-", "");
  const r = new Uint8Array(16);
  for (let index = 0; index < 16; index++) {
    r[index] = parseInt(uuid.substr(index * 2, 2), 16);
  }
  return r;
}

async function read_vless_header(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  cfg_uuid_str: string
): Promise<{
  hostname: string;
  port: number;
  data: Uint8Array;
  resp: Uint8Array;
}> {
  let readed_len = 0;
  let header = new Uint8Array();

  async function inner_read_until(offset: number): Promise<void> {
    while (readed_len < offset) {
      const { value, done } = await reader.read();
      if (done) throw new Error("header length too short");
      header = concat_typed_arrays(header, value!);
      readed_len += value!.length;
    }
  }

  await inner_read_until(1 + 16 + 1);

  const version = header[0];
  const uuid = header.slice(1, 1 + 16);
  const cfg_uuid = parse_uuid(cfg_uuid_str);
  if (!validate_uuid(uuid, cfg_uuid)) {
    throw new Error("invalid UUID");
  }
  const pb_len = header[1 + 16];
  const addr_plus1 = 1 + 16 + 1 + pb_len + 1 + 2 + 1;
  await inner_read_until(addr_plus1 + 1);

  const cmd = header[1 + 16 + 1 + pb_len];
  const COMMAND_TYPE_TCP = 1;
  if (cmd !== COMMAND_TYPE_TCP) {
    throw new Error(`unsupported command: ${cmd}`);
  }

  const port = (header[addr_plus1 - 1 - 2] << 8) + header[addr_plus1 - 1 - 1];
  const atype = header[addr_plus1 - 1];

  const ADDRESS_TYPE_IPV4 = 1;
  const ADDRESS_TYPE_STRING = 2;
  const ADDRESS_TYPE_IPV6 = 3;
  let header_len = -1;
  if (atype === ADDRESS_TYPE_IPV4) {
    header_len = addr_plus1 + 4;
  } else if (atype === ADDRESS_TYPE_IPV6) {
    header_len = addr_plus1 + 16;
  } else if (atype === ADDRESS_TYPE_STRING) {
    header_len = addr_plus1 + 1 + header[addr_plus1];
  }
  if (header_len < 0) {
    throw new Error("read address type failed");
  }
  await inner_read_until(header_len);

  const idx = addr_plus1;
  let hostname = "";
  if (atype === ADDRESS_TYPE_IPV4) {
    hostname = Array.from(header.slice(idx, idx + 4))
      .map((b) => b.toString())
      .join(".");
  } else if (atype === ADDRESS_TYPE_STRING) {
    hostname = new TextDecoder().decode(header.slice(idx + 1, idx + 1 + header[idx]));
  } else if (atype === ADDRESS_TYPE_IPV6) {
    hostname = Array.from({ length: 8 }, (_, i) =>
      ((header[idx + i * 2] << 8) + header[idx + i * 2 + 1]).toString(16)
    ).join(":");
  }

  if (!hostname) {
    log("error", "Failed to parse hostname");
    throw new Error("parse hostname failed");
  }

  log("info", `VLESS connection to ${hostname}:${port}`);
  return {
    hostname,
    port,
    data: header.slice(header_len),
    resp: new Uint8Array([version, 0]),
  };
}

async function parse_header(
  uuid_str: string,
  client: { readable: ReadableStream<Uint8Array> }
): Promise<any> {
  log("debug", "Starting to parse VLESS header");
  const reader = client.readable.getReader();
  try {
    const vless = await read_vless_header(reader, uuid_str);
    log("debug", "VLESS header parsed successfully");
    return vless;
  } catch (err) {
    log("error", `VLESS header parse error: ${err.message}`);
    throw new Error(`read vless header error: ${err.message}`);
  } finally {
    reader.releaseLock();
  }
}

// Remote connection
async function connect_remote(hostname: string, port: number): Promise<Deno.Conn> {
  const timeout = 8000;
  try {
    const conn = await Deno.connect({ hostname, port });
    log("info", `Connected to ${hostname}:${port}`);
    return conn;
  } catch (err) {
    log("error", `Connection failed: ${err.message}`);
    throw err;
  }
}

// Relay piping
function pipe_relay() {
  async function pump(
    src: ReadableStream<Uint8Array>,
    dest: WritableStream<Uint8Array>,
    first_packet: Uint8Array
  ): Promise<void> {
    if (first_packet.length > 0) {
      const writer = dest.getWriter();
      await writer.write(first_packet);
      writer.releaseLock();
    }

    try {
      await src.pipeTo(dest, {
        preventClose: false,
        preventAbort: false,
        preventCancel: false,
        signal: AbortSignal.timeout(SETTINGS.SESSION_TIMEOUT),
      });
    } catch (err) {
      if (!err.message.includes("aborted")) {
        log("error", "Relay error:", err.message);
      }
      throw err;
    }
  }
  return pump;
}

function relay(
  cfg: Settings,
  client: { readable: ReadableStream<Uint8Array>; writable: WritableStream<Uint8Array> },
  remote: Deno.Conn,
  vless: { data: Uint8Array; resp: Uint8Array }
): void {
  const pump = pipe_relay();
  let isClosing = false;

  const remoteStream = {
    readable: remote.readable,
    writable: remote.writable,
  };

  function cleanup(): void {
    if (!isClosing) {
      isClosing = true;
      try {
        remote.close();
      } catch (err) {
        if (!err.message.includes("aborted") && !err.message.includes("socket hang up")) {
          log("error", `Cleanup error: ${err.message}`);
        }
      }
    }
  }

  const uploader = pump(client.readable, remoteStream.writable, vless.data)
    .catch((err) => {
      if (!err.message.includes("aborted") && !err.message.includes("socket hang up")) {
        log("error", `Upload error: ${err.message}`);
      }
    })
    .finally(cleanup);

  const downloader = pump(remoteStream.readable, client.writable, vless.resp)
    .catch((err) => {
      if (!err.message.includes("aborted") && !err.message.includes("socket hang up")) {
        log("error", `Download error: ${err.message}`);
      }
    });

  downloader.finally(() => uploader).finally(cleanup);
}

// Session management
const sessions = new Map<string, Session>();

class Session {
  uuid: string;
  nextSeq: number = 0;
  downstreamStarted: boolean = false;
  lastActivity: number = Date.now();
  vlessHeader: any = null;
  remote: Deno.Conn | null = null;
  initialized: boolean = false;
  responseHeader: Uint8Array | null = null;
  headerSent: boolean = false;
  bufferedData: Map<number, Uint8Array> = new Map();
  cleaned: boolean = false;
  pendingPackets: Uint8Array[] = [];
  currentStreamRes: { writable: WritableStream<Uint8Array> } | null = null;
  pendingBuffers: Map<number, Uint8Array> = new Map();

  constructor(uuid: string) {
    this.uuid = uuid;
    log("debug", `Created new session with UUID: ${uuid}`);
  }

  async initializeVLESS(firstPacket: Uint8Array): Promise<boolean> {
    if (this.initialized) return true;

    try {
      log("debug", "Initializing VLESS connection from first packet");
      const readable = new ReadableStream({
        start(controller) {
          controller.enqueue(firstPacket);
          controller.close();
        },
      });

      const client = {
        readable,
        writable: new WritableStream(),
      };

      this.vlessHeader = await parse_header(SETTINGS.UUID, client);
      log("info", `VLESS header parsed: ${this.vlessHeader.hostname}:${this.vlessHeader.port}`);

      this.remote = await connect_remote(this.vlessHeader.hostname, this.vlessHeader.port);
      log("info", "Remote connection established");

      this.initialized = true;
      return true;
    } catch (err) {
      log("error", `Failed to initialize VLESS: ${err.message}`);
      return false;
    }
  }

  async processPacket(seq: number, data: Uint8Array): Promise<boolean> {
    try {
      this.pendingBuffers.set(seq, data);
      log("debug", `Buffered packet seq=${seq}, size=${data.length}`);

      while (this.pendingBuffers.has(this.nextSeq)) {
        const nextData = this.pendingBuffers.get(this.nextSeq)!;
        this.pendingBuffers.delete(this.nextSeq);

        if (!this.initialized && this.nextSeq === 0) {
          if (!await this.initializeVLESS(nextData)) {
            throw new Error("Failed to initialize VLESS connection");
          }
          this.responseHeader = this.vlessHeader.resp;
          await this._writeToRemote(this.vlessHeader.data);

          if (this.currentStreamRes) {
            this._startDownstreamResponse();
          }
        } else {
          if (!this.initialized) {
            log("warn", `Received out of order packet seq=${seq} before initialization`);
            continue;
          }
          await this._writeToRemote(nextData);
        }

        this.nextSeq++;
        log("debug", `Processed packet seq=${this.nextSeq - 1}`);
      }

      if (this.pendingBuffers.size > SETTINGS.MAX_BUFFERED_POSTS) {
        throw new Error("Too many buffered packets");
      }

      return true;
    } catch (err) {
      log("error", `Process packet error: ${err.message}`);
      throw err;
    }
  }

  startDownstream(res: { writable: WritableStream<Uint8Array> }): boolean {
    log("info", "Starting downstream");
    this.currentStreamRes = res;
    if (this.initialized && this.responseHeader) {
      this._startDownstreamResponse();
    }
    return true;
  }

  async _writeToRemote(data: Uint8Array): Promise<void> {
    if (!this.remote) {
      throw new Error("Remote connection not available");
    }
    const writer = this.remote.writable.getWriter();
    await writer.write(data);
    writer.releaseLock();
  }

  _startDownstreamResponse(): void {
    if (!this.currentStreamRes || !this.responseHeader) return;

    try {
      const writer = this.currentStreamRes.writable.getWriter();
      writer.write(this.responseHeader);
      this.headerSent = true;
      writer.releaseLock();

      this.remote!.readable.pipeTo(this.currentStreamRes.writable).catch((err) => {
        log("error", `Pipe error: ${err.message}`);
      });
    } catch (err) {
      log("error", `Error starting downstream: ${err.message}`);
      this.cleanup();
    }
  }

  cleanup(): void {
    if (!this.cleaned) {
      this.cleaned = true;
      log("debug", `Cleaning up session ${this.uuid}`);
      if (this.remote) {
        this.remote.close();
        this.remote = null;
      }
      this.initialized = false;
      this.headerSent = false;
    }
  }
}

// 获取ISP信息的函数
async function getISPInfo(): Promise<string> {
  try {
    const p = Deno.run({
      cmd: ["curl", "-s", "https://speed.cloudflare.com/meta"],
      stdout: "piped",
    });
    const output = await p.output();
    const metaInfo = new TextDecoder().decode(output);
    const parts = metaInfo.split('"');
    return (parts[25] + "-" + parts[17]).replace(/ /g, "_");
  } catch (err) {
    log("error", "Failed to get ISP info:", err.message);
    return "unknown";
  }
}

// 获取IP地址的函数
async function getIPAddress(): Promise<string> {
  if (DOMAIN) return DOMAIN;
  
  try {
    const p = Deno.run({
      cmd: ["curl", "-s", "--max-time", "2", "ipv4.ip.sb"],
      stdout: "piped",
    });
    const output = await p.output();
    return new TextDecoder().decode(output).trim();
  } catch (err) {
    try {
      const p = Deno.run({
        cmd: ["curl", "-s", "--max-time", "1", "ipv6.ip.sb"],
        stdout: "piped",
      });
      const output = await p.output();
      return `[${new TextDecoder().decode(output).trim()}]`;
    } catch (ipv6Err) {
      log("error", "Failed to get IP address:", ipv6Err.message);
      return "localhost";
    }
  }
}

// Utility function for padding
function generatePadding(min: number, max: number): string {
  const length = min + Math.floor(Math.random() * (max - min));
  return btoa(Array(length).fill("X").join(""));
}

// 初始化并启动服务器
async function initServer() {
  const ISP = await getISPInfo();
  const IP = await getIPAddress();

  serve(
    async (req: Request): Promise<Response> => {
      const url = new URL(req.url);
      const path = url.pathname;

      const headers = {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST",
        "Cache-Control": "no-store",
        "X-Accel-Buffering": "no",
        "X-Padding": generatePadding(100, 1000),
      };

      if (path === "/") {
        return new Response("Hello, World\n", {
          status: 200,
          headers: { "Content-Type": "text/plain" },
        });
      }

      if (path === `/${SUB_PATH}`) {
        const vlessURL = `vless://${UUID}@${IP}:${PORT}?encryption=none&security=none&sni=${IP}&fp=chrome&allowInsecure=1&type=xhttp&host=${IP}&path=${SETTINGS.XPATH}&mode=packet-up#${NAME}-${ISP}`;
        const base64Content = btoa(vlessURL);
        return new Response(base64Content + "\n", {
          status: 200,
          headers: { "Content-Type": "text/plain" },
        });
      }

      const pathMatch = path.match(new RegExp(`/${XPATH}/([^/]+)(?:/([0-9]+))?$`));
      if (!pathMatch) {
        return new Response("Not Found", { status: 404 });
      }

      const uuid = pathMatch[1];
      const seq = pathMatch[2] ? parseInt(pathMatch[2]) : null;

      if (req.method === "GET" && !seq) {
        let session = sessions.get(uuid);
        if (!session) {
          session = new Session(uuid);
          sessions.set(uuid, session);
          log("info", `Created new session for GET: ${uuid}`);
        }

        session.downstreamStarted = true;
        const { readable, writable } = new TransformStream();
        session.startDownstream({ writable });

        return new Response(readable, {
          status: 200,
          headers: {
            ...headers,
            "Content-Type": "application/octet-stream",
            "Transfer-Encoding": "chunked",
          },
        });
      }

      if (req.method === "POST" && seq !== null) {
        let session = sessions.get(uuid);
        if (!session) {
          session = new Session(uuid);
          sessions.set(uuid, session);
          log("info", `Created new session for POST: ${uuid}`);

          setTimeout(() => {
            const currentSession = sessions.get(uuid);
            if (currentSession && !currentSession.downstreamStarted) {
              log("warn", `Session ${uuid} timed out without downstream`);
              currentSession.cleanup();
              sessions.delete(uuid);
            }
          }, SETTINGS.SESSION_TIMEOUT);
        }

        const data = await req.arrayBuffer();
        const buffer = new Uint8Array(data);
        log("info", `Processing packet: seq=${seq}, size=${buffer.length}`);

        try {
          await session.processPacket(seq, buffer);
          return new Response(null, { status: 200, headers });
        } catch (err) {
          log("error", `Failed to process POST request: ${err.message}`);
          session.cleanup();
          sessions.delete(uuid);
          return new Response(null, { status: 500 });
        }
      }

      return new Response("Not Found", { status: 404 });
    },
    { 
      port: PORT, 
      onListen: () => {
        addAccessTask();
        console.log(`Server is running on port ${PORT}`);
        log("info", "=================================");
        log("info", `Log level: ${SETTINGS.LOG_LEVEL}`);
        log("info", `Max buffered posts: ${SETTINGS.MAX_BUFFERED_POSTS}`);
        log("info", `Max POST size: ${SETTINGS.MAX_POST_SIZE}KB`);
        log("info", `Max buffer size: ${SETTINGS.BUFFER_SIZE}KB`);
        log("info", `Session timeout: ${SETTINGS.CHUNK_SIZE}bytes`);
        log("info", "=================================");
      }
    }
  );
}

// 启动服务器
initServer().catch(err => {
  console.error("Failed to start server:", err);
  Deno.exit(1);
});
