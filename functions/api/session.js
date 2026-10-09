import { json } from '../../shared/security.js';
export function onRequestGet(context) {
  return json(context.data.user);
}
