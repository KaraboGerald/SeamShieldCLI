// Deliberately vulnerable fixture: admin page with no guard at all.
export default function AdminPage() {
  return (
    <main>
      <h1>Admin</h1>
      <button>Delete everything</button>
    </main>
  );
}
