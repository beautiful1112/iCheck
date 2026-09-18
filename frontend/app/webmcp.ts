"use client";

import { useEffect, useRef } from "react";

type WebMCPContext = {
  registerTool(
    tool: {
      name: string;
      title: string;
      description: string;
      inputSchema: object;
      annotations: { readOnlyHint: boolean; untrustedContentHint: boolean };
      execute(input: unknown): Promise<unknown>;
    },
    options?: { signal?: AbortSignal },
  ): void | Promise<void>;
};

declare global {
  interface Document {
    readonly modelContext?: WebMCPContext;
  }
}

export function useAlertWebMCP(
  acknowledgeAlert: (alertId: string) => Promise<void>,
) {
  const actionRef = useRef(acknowledgeAlert);

  useEffect(() => {
    actionRef.current = acknowledgeAlert;
  }, [acknowledgeAlert]);

  useEffect(() => {
    const context = document.modelContext;
    if (!context?.registerTool) return;
    const lifecycle = new AbortController();

    void Promise.resolve(
      context.registerTool(
        {
          name: "acknowledge_alert",
          title: "Acknowledge alert",
          description:
            "Acknowledge one visible iCheck alert by ID and update the alert center.",
          inputSchema: {
            type: "object",
            properties: {
              alertId: {
                type: "string",
                description: "The alert ID displayed in the alert center.",
              },
            },
            required: ["alertId"],
            additionalProperties: false,
          },
          annotations: { readOnlyHint: false, untrustedContentHint: false },
          async execute(input: unknown) {
            if (
              typeof input !== "object" ||
              input === null ||
              !("alertId" in input) ||
              typeof input.alertId !== "string" ||
              input.alertId.length === 0
            ) {
              throw new Error("alertId must be a non-empty string");
            }
            await actionRef.current(input.alertId);
            return { alertId: input.alertId, status: "acknowledged" };
          },
        },
        { signal: lifecycle.signal },
      ),
    ).catch(() => undefined);

    return () => lifecycle.abort();
  }, []);
}
