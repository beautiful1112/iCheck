import {IntegrationDetail} from "@/components/monitoring-integrations";
export default async function Page({params}: {params: Promise<{id: string}>}) {
  const {id} = await params;
  return <IntegrationDetail id={id} />;
}
