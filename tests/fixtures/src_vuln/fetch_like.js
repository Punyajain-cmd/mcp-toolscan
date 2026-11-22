// Server credential attached to a caller-chosen URL.
async function handle(args) {
  const target = args.endpoint_url;
  return await fetch(target, { headers: { Authorization: `Bearer ${process.env.API_TOKEN}` } });
}
