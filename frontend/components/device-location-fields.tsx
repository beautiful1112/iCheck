"use client";
import { Input } from "@/components/ui/input";
import type { DeviceLocation } from "@/lib/device-onboarding";

export function DeviceLocationFields({ value, onChange }: {
  value: DeviceLocation;
  onChange: (value: DeviceLocation) => void;
}) {
  return <fieldset className="mt-3 rounded-lg border border-slate-200 p-3">
    <legend className="px-1 text-sm font-medium">Physical location (optional)</legend>
    <p className="mb-3 text-xs text-muted-foreground">Leave any level blank. Location does not change credentials or Collector permissions. Height is the device’s rack U position.</p>
    <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
      {(["zone", "building", "floor", "room", "rack"] as const).map(field => <label key={field} className="text-xs font-medium capitalize">
        {field[0].toUpperCase() + field.slice(1)}<Input value={value[field] || ""} maxLength={128} placeholder="Not assigned" className="mt-1"
          onChange={event => onChange({ ...value, [field]: event.target.value || null })} />
      </label>)}
      <label className="text-xs font-medium">Height (rack U)
        <Input type="number" min={1} max={1000} step={1} value={value.height ?? ""} placeholder="Not assigned" className="mt-1"
          onChange={event => onChange({ ...value, height: event.target.value ? Number(event.target.value) : null })} />
      </label>
    </div>
  </fieldset>;
}
