/*
Copyright 2020 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package metal

import (
	"context"
	"fmt"
	"os"

	"github.com/bufbuild/connect-go"
	v1 "github.com/majst01/metal-dns/api/v1"

	"github.com/majst01/metal-dns/pkg/client"
	log "github.com/sirupsen/logrus"

	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/plan"
	"sigs.k8s.io/external-dns/provider"
)

const (
	metalCreate = "CREATE"
	metalDelete = "DELETE"
	metalUpdate = "UPDATE"
	metalTTL    = uint32(3600)
)

// MetalProvider is an implementation of Provider for Metal DNS.
type MetalProvider struct {
	provider.BaseProvider
	client client.Client

	domainFilter endpoint.DomainFilter
}

// MetalChanges differentiates between ChangActions.
type MetalChanges struct {
	Action string

	ResourceRecordSet *v1.RecordServiceUpdateRequest
}

// NewMetalProvider initializes a new Metal BNS based provider
func NewMetalProvider(ctx context.Context, domainFilter endpoint.DomainFilter, dryRun bool) (*MetalProvider, error) {
	// We do not support dry running, exit safely instead of surprising the user
	// TODO: add dry run support
	if dryRun {
		return nil, fmt.Errorf("metal-dns provider does not currently support dry-run")
	}
	apiKey, ok := os.LookupEnv("METAL_DNS_JWT_TOKEN")
	if !ok {
		return nil, fmt.Errorf("no token found")
	}
	config := client.DialConfig{Token: apiKey}
	apiURL, ok := os.LookupEnv("METAL_DNS_API_URL")
	if ok {
		config.BaseURL = apiURL
	}
	log.Debug("configuring metal-dns provider")

	c := client.New(ctx, config)

	p := &MetalProvider{
		client:       c,
		domainFilter: domainFilter,
	}

	return p, nil
}

// Zones returns list of hosted zones
func (p *MetalProvider) Zones(ctx context.Context) ([]v1.Domain, error) {
	zones, err := p.fetchZones(ctx)
	if err != nil {
		return nil, err
	}

	return zones, nil
}

// Records returns the list of records.
func (p *MetalProvider) Records(ctx context.Context) ([]*endpoint.Endpoint, error) {
	zones, err := p.Zones(ctx)
	if err != nil {
		return nil, err
	}

	var endpoints []*endpoint.Endpoint

	for _, zone := range zones {
		records, err := p.fetchRecords(ctx, zone.Name)
		if err != nil {
			return nil, err
		}

		for _, r := range records {
			if provider.SupportedRecordType(r.Type.String()) {
				name := fmt.Sprintf("%s.%s", r.Name, zone.Name)

				// root name is identified by the empty string and should be
				// translated to zone name for the endpoint entry.
				if r.Name == "" {
					name = zone.Name
				}

				endpoints = append(endpoints, endpoint.NewEndpointWithTTL(name, r.Type.String(), endpoint.TTL(r.Ttl), r.Data))
			}
		}
	}

	return endpoints, nil
}

func (p *MetalProvider) fetchRecords(ctx context.Context, domain string) ([]v1.Record, error) {
	var allRecords []v1.Record
	listOptions := &v1.RecordServiceListRequest{
		Domain: domain,
	}

	records, err := p.client.Record().List(ctx, connect.NewRequest(listOptions))
	if err != nil {
		return nil, err
	}
	for _, record := range records.Msg.Records {
		allRecords = append(allRecords, *record)
	}
	return allRecords, nil
}

func (p *MetalProvider) fetchZones(ctx context.Context) ([]v1.Domain, error) {
	var zones []v1.Domain
	listRequest := &v1.DomainServiceListRequest{}

	allZones, err := p.client.Domain().List(ctx, connect.NewRequest(listRequest))
	if err != nil {
		return nil, err
	}

	for _, zone := range allZones.Msg.Domains {
		if p.domainFilter.Match(zone.Name) {
			zones = append(zones, *zone)
		}
	}

	return zones, nil
}

func (p *MetalProvider) submitChanges(ctx context.Context, changes []*MetalChanges) error {
	if len(changes) == 0 {
		log.Infof("All records are already up to date")
		return nil
	}

	zones, err := p.Zones(ctx)
	if err != nil {
		return err
	}

	zoneChanges := separateChangesByZone(zones, changes)

	for zoneName, changes := range zoneChanges {
		for _, change := range changes {
			log.WithFields(log.Fields{
				"record": change.ResourceRecordSet.Name,
				"type":   change.ResourceRecordSet.Type,
				"ttl":    change.ResourceRecordSet.Ttl,
				"action": change.Action,
				"zone":   zoneName,
			}).Info("Changing record.")

			switch change.Action {
			case metalCreate:
				if _, err := p.client.Record().Create(ctx, connect.NewRequest(&v1.RecordServiceCreateRequest{Name: zoneName, Data: change.ResourceRecordSet.Name, Type: change.ResourceRecordSet.Type, Ttl: change.ResourceRecordSet.Ttl})); err != nil {
					return err
				}
			case metalDelete:
				if _, err := p.client.Record().Delete(ctx, connect.NewRequest(&v1.RecordServiceDeleteRequest{Name: zoneName})); err != nil {
					return err
				}
			case metalUpdate:
				if _, err := p.client.Record().Update(ctx, connect.NewRequest(&v1.RecordServiceUpdateRequest{Name: zoneName, Data: change.ResourceRecordSet.Name, Type: change.ResourceRecordSet.Type, Ttl: change.ResourceRecordSet.Ttl})); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// ApplyChanges applies a given set of changes in a given zone.
func (p *MetalProvider) ApplyChanges(ctx context.Context, changes *plan.Changes) error {

	// Create
	for _, change := range changes.Create {
		log.Debugf("CREATE: %+v", change)
	}
	// Update
	for _, change := range changes.UpdateNew {
		log.Debugf("UPDATE-NEW: %+v", change)
	}
	// Delete
	for _, change := range changes.Delete {
		log.Debugf("DELETE: %+v", change)
	}
	combinedChanges := make([]*MetalChanges, 0, len(changes.Create)+len(changes.UpdateNew)+len(changes.Delete))

	combinedChanges = append(combinedChanges, newMetalChanges(metalCreate, changes.Create)...)
	combinedChanges = append(combinedChanges, newMetalChanges(metalUpdate, changes.UpdateNew)...)
	combinedChanges = append(combinedChanges, newMetalChanges(metalDelete, changes.Delete)...)

	return p.submitChanges(ctx, combinedChanges)
}

func newMetalChanges(action string, endpoints []*endpoint.Endpoint) []*MetalChanges {
	changes := make([]*MetalChanges, 0, len(endpoints))
	ttl := metalTTL
	for _, e := range endpoints {
		if e.RecordTTL.IsConfigured() {
			ttl = uint32(e.RecordTTL)
		}

		change := &MetalChanges{
			Action: action,
			ResourceRecordSet: &v1.RecordServiceUpdateRequest{
				Type: client.ToV1RecordType(e.RecordType),
				Name: e.DNSName,
				Data: e.Targets[0],
				Ttl:  ttl,
			},
		}

		changes = append(changes, change)
	}
	return changes
}

func separateChangesByZone(zones []v1.Domain, changes []*MetalChanges) map[string][]*MetalChanges {
	change := make(map[string][]*MetalChanges)
	zoneNameID := provider.ZoneIDName{}

	for _, z := range zones {
		zoneNameID.Add(z.Name, z.Name)
		change[z.Name] = []*MetalChanges{}
	}

	for _, c := range changes {
		zone, _ := zoneNameID.FindZone(c.ResourceRecordSet.Name)
		if zone == "" {
			log.Debugf("Skipping record %s because no hosted zone matching record DNS Name was detected", c.ResourceRecordSet.Name)
			continue
		}
		change[zone] = append(change[zone], c)
	}
	return change
}
