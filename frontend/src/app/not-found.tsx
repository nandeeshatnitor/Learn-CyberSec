import Link from "next/link";

export default function NotFound() {
  return (
    <div className="space-y-4">
      <h1 className="text-3xl font-bold">Page not found</h1>
      <p className="text-muted-foreground">
        That address is not valid. CVE IDs look like <code className="font-mono">CVE-2021-44228</code>.
      </p>
      <Link href="/" className="text-primary hover:underline">
        Back to search
      </Link>
    </div>
  );
}
