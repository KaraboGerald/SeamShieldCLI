// Deliberately vulnerable fixture: anyone can call this endpoint.
export async function POST(request) {
  const body = await request.formData();
  return Response.json({ stored: body.has("file") });
}
