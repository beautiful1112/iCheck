import SourceQualificationWorkspace from "../workspace";

export default async function SourceQualificationPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return <SourceQualificationWorkspace sourceId={id} />;
}
