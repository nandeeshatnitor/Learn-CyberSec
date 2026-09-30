import { getHealth } from "@/lib/api";
import { Badge } from "@/components/ui/badge";

/** Server component: asks the backend for /api/health and shows the result. */
export async function ApiStatus() {
  const result = await getHealth();

  if (!result.ok) {
    return (
      <Badge variant="destructive" data-testid="api-status">
        API unreachable
      </Badge>
    );
  }
  const { status, version } = result.data;
  return (
    <Badge variant={status === "ok" ? "default" : "warning"} data-testid="api-status">
      API {status} · v{version}
    </Badge>
  );
}
