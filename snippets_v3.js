import { connect } from 'cloudflare:sockets';

// ============ 预编译常量（V8 内联缓存友好） ============
const UUID = new Uint8Array([0x55,0xd9,0xec,0x38,0x1b,0x8a,0x45,0x4b,0x98,0x1a,0x6a,0xcf,0xe8,0xf5,0x6d,0x8c]);
const PROXY_HOST = 'sjc.o00o.ooo';
const PROXY_PORT = 443;

// 地址类型常量 - 使用位运算友好的值
const ATYPE_IPV4 = 1;
const ATYPE_DOMAIN = 2;
const ATYPE_IPV6 = 3;

// 流控制常量 - 基于典型网络MTU优化
const HIGH_WATER_MARK = 65536;  // 64KB - 触发背压
const LOW_WATER_MARK = 16384;   // 16KB - 恢复写入
const CHUNK_SIZE = 16384;       // 16KB - 单次读取块大小

// ============ 单例复用 ============
const textDecoder = new TextDecoder();
const textEncoder = new TextEncoder();

// ============ 类型稳定的返回对象 ============
// 预分配固定形状对象 - 避免 hidden class 变化
const createParseResult = (host, end, ok) => ({ host, end, ok });
const PARSE_ERROR = Object.freeze(createParseResult('', 0, false));

const createDecodeResult = (data, ok) => ({ data, ok });
const DECODE_ERROR = Object.freeze(createDecodeResult(null, false));

// ============ 预编译响应（避免重复创建） ============
const RESP_426 = Object.freeze({ status: 426, headers: { Upgrade: 'websocket' } });
const RESP_400 = Object.freeze({ status: 400 });
const RESP_403 = Object.freeze({ status: 403 });
const RESP_502 = Object.freeze({ status: 502 });

const makeResponse = (preset) => new Response(null, preset);

// ============ Base64 解码（类型稳定） ============
const decodeBase64 = (str) => {
  try {
    const binary = atob(str.replace(/-/g, '+').replace(/_/g, '/'));
    const len = binary.length;
    const arr = new Uint8Array(len);
    // 展开循环 - 4字节一组处理
    let i = 0;
    const end4 = len & ~3;
    for (; i < end4; i += 4) {
      arr[i] = binary.charCodeAt(i);
      arr[i + 1] = binary.charCodeAt(i + 1);
      arr[i + 2] = binary.charCodeAt(i + 2);
      arr[i + 3] = binary.charCodeAt(i + 3);
    }
    for (; i < len; i++) {
      arr[i] = binary.charCodeAt(i);
    }
    return createDecodeResult(arr, true);
  } catch {
    return DECODE_ERROR;
  }
};

// ============ UUID 验证（完全展开，避免分支预测失败） ============
const verifyUUID = (data) => {
  // 使用按位与合并比较 - 任何不匹配都会导致结果为0
  return (
    ((data[1] ^ UUID[0]) | (data[2] ^ UUID[1]) | (data[3] ^ UUID[2]) | (data[4] ^ UUID[3]) |
     (data[5] ^ UUID[4]) | (data[6] ^ UUID[5]) | (data[7] ^ UUID[6]) | (data[8] ^ UUID[7]) |
     (data[9] ^ UUID[8]) | (data[10] ^ UUID[9]) | (data[11] ^ UUID[10]) | (data[12] ^ UUID[11]) |
     (data[13] ^ UUID[12]) | (data[14] ^ UUID[13]) | (data[15] ^ UUID[14]) | (data[16] ^ UUID[15])) === 0
  );
};

// ============ 地址解析（类型稳定返回） ============
const parseAddress = (data, offset) => {
  const atype = data[offset + 3];
  const base = offset + 4;
  const dataLen = data.length;

  if (atype === ATYPE_DOMAIN) {
    const domainLen = data[base];
    const end = base + 1 + domainLen;
    if (end > dataLen) return PARSE_ERROR;
    return createParseResult(textDecoder.decode(data.subarray(base + 1, end)), end, true);
  }

  if (atype === ATYPE_IPV4) {
    const end = base + 4;
    if (end > dataLen) return PARSE_ERROR;
    // 内联字符串构建 - 避免数组join
    return createParseResult(
      data[base] + '.' + data[base + 1] + '.' + data[base + 2] + '.' + data[base + 3],
      end,
      true
    );
  }

  if (atype === ATYPE_IPV6) {
    const end = base + 16;
    if (end > dataLen) return PARSE_ERROR;
    const view = new DataView(data.buffer, data.byteOffset + base, 16);
    // 内联十六进制转换
    return createParseResult(
      view.getUint16(0).toString(16) + ':' +
      view.getUint16(2).toString(16) + ':' +
      view.getUint16(4).toString(16) + ':' +
      view.getUint16(6).toString(16) + ':' +
      view.getUint16(8).toString(16) + ':' +
      view.getUint16(10).toString(16) + ':' +
      view.getUint16(12).toString(16) + ':' +
      view.getUint16(14).toString(16),
      end,
      true
    );
  }

  return PARSE_ERROR;
};

// ============ TCP 连接器 ============
const connectTCP = async (host, port, useFallback) => {
  const targetHost = useFallback ? PROXY_HOST : host;
  const targetPort = useFallback ? PROXY_PORT : port;
  const socket = connect({ hostname: targetHost, port: targetPort });
  await socket.opened;
  return socket;
};

// ============ 连接状态管理（类属性类型固定） ============
class ConnectionState {
  constructor() {
    // 固定属性形状 - 避免 hidden class 迁移
    this.closed = false;
    this.serverSocket = null;
    this.tcpSocket = null;
    this.uplinkWriter = null;
    this.downlinkWriter = null;
  }

  init(server, tcp) {
    this.serverSocket = server;
    this.tcpSocket = tcp;
  }

  shutdown() {
    if (this.closed) return;
    this.closed = true;

    // 使用 queueMicrotask 延迟清理，避免阻塞热路径
    queueMicrotask(() => {
      this._safeClose(this.serverSocket);
      this._safeClose(this.tcpSocket);
      this._safeAbort(this.uplinkWriter);
      this._safeAbort(this.downlinkWriter);
    });
  }

  _safeClose(resource) {
    try { resource?.close?.(); } catch {}
  }

  _safeAbort(writer) {
    try { writer?.abort?.(); } catch {}
  }
}

// ============ 首帧构建（每请求独立缓冲区，避免竞态） ============
const buildFirstFrame = (chunk) => {
  const len = chunk.length;
  const frame = new Uint8Array(len + 2);
  // frame[0] = 0; frame[1] = 0; // Uint8Array 默认为0，无需显式设置
  frame.set(chunk, 2);
  return frame;
};

// ============ 上行数据管道（WebSocket -> TCP） ============
const createUplinkPipe = (state, initialData, tcpWritable) => {
  const writer = tcpWritable.getWriter();
  state.uplinkWriter = writer;

  let pendingWrites = 0;
  const MAX_PENDING = 4; // 最大并发写入数

  const writeChunk = async (chunk) => {
    if (state.closed) return;

    // 背压控制：等待 writer ready
    pendingWrites++;
    if (pendingWrites > MAX_PENDING) {
      await writer.ready;
    }

    try {
      await writer.write(chunk);
    } catch {
      state.shutdown();
    } finally {
      pendingWrites--;
    }
  };

  // 写入初始数据
  if (initialData && initialData.length > 0) {
    writeChunk(initialData);
  }

  // 返回消息处理器（单态函数）
  return (event) => {
    if (state.closed) return;

    const payload = event.data;
    let chunk;

    // 类型判断 - ArrayBuffer 是最常见情况，放在前面
    if (payload instanceof ArrayBuffer) {
      chunk = new Uint8Array(payload);
    } else if (payload instanceof Uint8Array) {
      chunk = payload;
    } else if (typeof payload === 'string') {
      chunk = textEncoder.encode(payload);
    } else {
      return; // 未知类型，忽略
    }

    writeChunk(chunk);
  };
};

// ============ 下行数据管道（TCP -> WebSocket） ============
const createDownlinkPipe = (state, serverSocket, tcpReadable) => {
  const reader = tcpReadable.getReader();
  let isFirstChunk = true;

  const pump = async () => {
    try {
      while (!state.closed) {
        const { done, value } = await reader.read();

        if (done) {
          state.shutdown();
          return;
        }

        if (state.closed) return;

        if (isFirstChunk) {
          isFirstChunk = false;
          const frame = buildFirstFrame(value);
          serverSocket.send(frame);
        } else {
          // 直接发送，避免包装
          serverSocket.send(value);
        }
      }
    } catch {
      state.shutdown();
    } finally {
      try { reader.releaseLock(); } catch {}
    }
  };

  // 启动读取循环
  pump();
};

// ============ 主处理器 ============
export default {
  async fetch(request) {
    // ---- 快速路径检查 ----
    const upgradeHeader = request.headers.get('Upgrade');
    if (upgradeHeader !== 'websocket') {
      return makeResponse(RESP_426);
    }

    const protocol = request.headers.get('Sec-WebSocket-Protocol');
    if (!protocol) {
      return makeResponse(RESP_400);
    }

    // ---- 解码 payload ----
    const decoded = decodeBase64(protocol);
    if (!decoded.ok) {
      return makeResponse(RESP_400);
    }
    const data = decoded.data;

    // ---- 长度验证 ----
    if (data.length < 18) {
      return makeResponse(RESP_400);
    }

    // ---- UUID 验证 ----
    if (!verifyUUID(data)) {
      return makeResponse(RESP_403);
    }

    // ---- 计算地址偏移 ----
    const addrOffset = 18 + data[17];
    if (addrOffset + 4 > data.length) {
      return makeResponse(RESP_400);
    }

    // ---- 解析端口（大端序） ----
    const port = (data[addrOffset + 1] << 8) | data[addrOffset + 2];

    // ---- 解析地址 ----
    const addr = parseAddress(data, addrOffset);
    if (!addr.ok) {
      return makeResponse(RESP_400);
    }

    // ---- 建立 TCP 连接（带回退） ----
    let tcp;
    try {
      tcp = await connectTCP(addr.host, port, false);
    } catch {
      try {
        tcp = await connectTCP(addr.host, port, true);
      } catch {
        return makeResponse(RESP_502);
      }
    }

    // ---- 创建 WebSocket 对 ----
    const pair = new WebSocketPair();
    const [client, server] = pair;
    server.accept();

    // ---- 初始化连接状态 ----
    const state = new ConnectionState();
    state.init(server, tcp);

    // ---- 提取初始数据 ----
    const initialData = data.length > addr.end ? data.subarray(addr.end) : null;

    // ---- 建立上行管道 ----
    const messageHandler = createUplinkPipe(state, initialData, tcp.writable);
    server.addEventListener('message', messageHandler);
    server.addEventListener('close', () => state.shutdown());
    server.addEventListener('error', () => state.shutdown());

    // ---- 建立下行管道 ----
    createDownlinkPipe(state, server, tcp.readable);

    // ---- 返回 WebSocket 响应 ----
    return new Response(null, { status: 101, webSocket: client });
  }
};
