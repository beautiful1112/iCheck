import {redirect} from "next/navigation";
import {StudioLibrary} from "@/components/studio-library";
import {legacyStudioDestination} from "@/lib/studio-library";

export default async function StudioPage({searchParams}: {searchParams: Promise<Record<string, string | string[] | undefined>>}) {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(await searchParams)) if (typeof value === "string") query.set(key, value);
  const destination = legacyStudioDestination(query);
  if (destination) redirect(destination);
  return <StudioLibrary />;
}
