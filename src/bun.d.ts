declare namespace Bun {
  type RouteHandler = (req: Request) => Response | Promise<Response>;

  type ServeOptions = {
    port: number;
    routes?: Record<string, RouteHandler>;
    fetch?: RouteHandler;
  };

  type Server = {
    port: number;
    stop: (closeActiveConnections?: boolean) => void;
  };

  const env: Record<string, string | undefined>;

  function serve(options: ServeOptions): Server;
}

declare module "bun:test" {
  type TestCallback = () => unknown | Promise<unknown>;

  export function afterEach(callback: TestCallback): void;
  export function describe(name: string, callback: TestCallback): void;
  export function test(name: string, callback: TestCallback): void;
  export function expect(actual: unknown): {
    toBe(expected: unknown): void;
    toHaveLength(expected: number): void;
    toMatchObject(expected: unknown): void;
  };
}
