function explode(): never {
  const detail: string = "mapped failure";
  throw new Error(detail);
}
explode();
