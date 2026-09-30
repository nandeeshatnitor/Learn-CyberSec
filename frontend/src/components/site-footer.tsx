export function SiteFooter() {
  return (
    <footer className="mt-16 border-t">
      <div className="mx-auto max-w-5xl px-4 py-6 text-sm text-muted-foreground">
        <p>
          <strong className="text-foreground">Educational use only.</strong> This platform helps
          you understand publicly known vulnerabilities. Only test on systems you own or have
          explicit written permission to test. Information from external sources is untrusted
          and must be verified against the cited originals.
        </p>
      </div>
    </footer>
  );
}
