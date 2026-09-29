import { apiGateway } from "./apiGateway";
import { mockGateway } from "./mockGateway";

// Production always uses the same-origin API.  Tests retain the upstream mock so
// visual behavior can be exercised without constructing security authority.
export const gateway = import.meta.env.MODE === "test" ? mockGateway : apiGateway;
export const gatewayMode = import.meta.env.MODE === "test" ? "mock" : "live";
