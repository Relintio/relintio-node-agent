import { UltimateProtectorNodeAgent } from './node-agent.js';

/**
 * Express middleware.
 *
 * @param {import('./types.js').UltimateProtectorOptions} options
 */
export function ultimateProtectorExpress(options) {
  const agent = new UltimateProtectorNodeAgent(options);

  return function ultimateProtectorMiddleware(req, res, next) {
    agent.handleExpress(req, res, next).catch(next);
  };
}
