import { Outlet } from "react-router-dom";
import Sidebar from "./Sidebar";
import TopNavbar from "./TopNavbar";

export default function AppLayout() {
  return (
    <div className="flex min-h-screen bg-navy-900 text-foreground overflow-hidden">
      <Sidebar />
      <div className="flex-1 ml-64 flex flex-col h-screen overflow-hidden">
        <TopNavbar />
        <main className="flex-1 overflow-y-auto bg-[#030712]/50 p-6">
          <div className="mx-auto max-w-7xl">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
}
