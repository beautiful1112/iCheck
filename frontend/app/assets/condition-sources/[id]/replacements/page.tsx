import SourceReplacementWorkspace from "../../replacement-workspace";

export default async function SourceReplacementPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return <SourceReplacementWorkspace key={id} sourceId={id} />;
}
