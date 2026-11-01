// Error type and codes shared by every engine module; same numbers as xray_forge/engine/rpc.py.
export const PARSE_ERROR = -32700;
export const INVALID_REQUEST = -32600;
export const METHOD_NOT_FOUND = -32601;
export const INVALID_PARAMS = -32602;
export const APP_ERROR = -32000;

export class RpcError extends Error {
  constructor(code, message, data) {
    super(message);
    this.name = 'RpcError';
    this.code = code;
    if (data !== undefined) this.data = data;
  }
}

export const invalidParams = (message) => new RpcError(INVALID_PARAMS, message);
