import { useQuery } from '@tanstack/react-query';
import { api } from '@/services/api';

export function useRepositories() {
  return useQuery({
    queryKey: ['repositories'],
    queryFn: api.getRepositories,
    retry: false,
    initialData: [] // Empty array as initial state. Backend must return real data.
  });
}

export function useVulnerabilities() {
  return useQuery({
    queryKey: ['vulnerabilities'],
    queryFn: api.getVulnerabilities,
    retry: false,
    initialData: [] 
  });
}

export function useDashboardMetrics() {
  return useQuery({
    queryKey: ['dashboard-metrics'],
    queryFn: api.getDashboardMetrics,
    retry: false,
    initialData: null
  });
}

export function useBusinessRisk() {
  return useQuery({
    queryKey: ['business-risk'],
    queryFn: api.getBusinessRisk,
    retry: false,
    initialData: null
  });
}

export function useComplianceStatus() {
  return useQuery({
    queryKey: ['compliance'],
    queryFn: api.getComplianceStatus,
    retry: false,
    initialData: null
  });
}
