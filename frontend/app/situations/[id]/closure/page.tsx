import {redirect} from "next/navigation";

/** Retired product route. Historical records remain in the backend. */
export default function RetiredPage() {
  redirect("/alerts");
}
