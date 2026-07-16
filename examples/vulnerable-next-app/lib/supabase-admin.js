// Deliberately vulnerable fixture — fake service-role JWT below.
import { createClient } from "@supabase/supabase-js";

export const supabaseAdmin = createClient(
  "https://example.supabase.co",
  "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIn0.FAKEFIXTURESIGNATURE",
);
