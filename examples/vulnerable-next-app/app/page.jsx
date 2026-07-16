export default function Page() {
  return (
    <main>
      <h1>Totally Shipped It</h1>
      <p>{process.env.NEXT_PUBLIC_APP_SECRET}</p>
    </main>
  );
}
