import { createRouter, createRoute, createRootRoute, Outlet } from "@tanstack/react-router";
import LandingPage from "../features/landing/LandingPage";
import OverviewPage from "../features/overview/OverviewPage";
import VerificationPage from "../features/verification/VerificationPage";
import ReportsListPage from "../features/reports/ReportsListPage";
import TrustReportPage from "../features/reports/TrustReportPage";
import HistoryPage from "../features/history/HistoryPage";
import SettingsPage from "../features/settings/SettingsPage";
import PoliciesPage from "../features/policies/PoliciesPage";
import BatchesPage from "../features/batches/BatchesPage";
import AttestationViewerPage from "../features/attestation/AttestationViewerPage";
import { AppShell } from "../components/layout/AppShell";

const rootRoute = createRootRoute({
  component: Outlet,
});

const landingRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/",
  component: LandingPage,
});

const appRoute = createRoute({
  getParentRoute: () => rootRoute,
  id: "app",
  component: AppShell,
});

const overviewRoute = createRoute({
  getParentRoute: () => appRoute,
  path: "/overview",
  component: OverviewPage,
});

const verifyRoute = createRoute({
  getParentRoute: () => appRoute,
  path: "/verify",
  component: VerificationPage,
});

const reportsRoute = createRoute({
  getParentRoute: () => appRoute,
  path: "/reports",
  component: ReportsListPage,
});

const reportDetailRoute = createRoute({
  getParentRoute: () => appRoute,
  path: "/reports/$reportId",
  component: TrustReportPage,
});

const batchesRoute = createRoute({
  getParentRoute: () => appRoute,
  path: "/batches",
  component: BatchesPage,
});

const policiesRoute = createRoute({
  getParentRoute: () => appRoute,
  path: "/policies",
  component: PoliciesPage,
});

const attestationsRoute = createRoute({
  getParentRoute: () => appRoute,
  path: "/attestations",
  component: AttestationViewerPage,
});

const historyRoute = createRoute({
  getParentRoute: () => appRoute,
  path: "/history",
  component: HistoryPage,
});

const settingsRoute = createRoute({
  getParentRoute: () => appRoute,
  path: "/settings",
  component: SettingsPage,
});

const routeTree = rootRoute.addChildren([
  landingRoute,
  appRoute.addChildren([
    overviewRoute,
    verifyRoute,
    reportsRoute,
    reportDetailRoute,
    batchesRoute,
    policiesRoute,
    attestationsRoute,
    historyRoute,
    settingsRoute,
  ]),
]);

export const router = createRouter({ routeTree });

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}
