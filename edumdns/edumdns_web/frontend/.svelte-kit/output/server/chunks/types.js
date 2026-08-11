function hasPermission(permissions, permission) {
  return permissions.some((p) => p.permission === "Full" || p.permission === permission);
}
export {
  hasPermission as h
};
