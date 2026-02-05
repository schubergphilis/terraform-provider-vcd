package vcd

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/vmware/go-vcloud-director/v2/govcd"
	"github.com/vmware/go-vcloud-director/v2/types/v56"
)

type NsxtFirewallRuleV2 struct {
	// ID contains UUID (e.g. d0bf5d51-f83a-489a-9323-1661024874b8)
	ID string `json:"id,omitempty"`
	// Name - API does not enforce uniqueness
	Name string `json:"name"`
	// Action field. Can be 'ALLOW', 'DROP'
	// Deprecated in favor of ActionValue in VCD 10.2.2+ (API V35.2)
	Action string `json:"action,omitempty"`

	// ActionValue replaces deprecated field Action and defines action to be applied to all the
	// traffic that meets the firewall rule criteria. It determines if the rule permits or blocks
	// traffic. Property is required if action is not set. Below are valid values:
	// * ALLOW permits traffic to go through the firewall.
	// * DROP blocks the traffic at the firewall. No response is sent back to the source.
	// * REJECT blocks the traffic at the firewall. A response is sent back to the source.
	ActionValue string `json:"actionValue,omitempty"`

	// Active allows to enable or disable the rule
	Active bool `json:"active"`
	// SourceFirewallGroups contains a list of references to Firewall Groups. Empty list means 'Any'
	SourceFirewallGroups []types.OpenApiReference `json:"sourceFirewallGroups,omitempty"`
	// DestinationFirewallGroups contains a list of references to Firewall Groups. Empty list means 'Any'
	DestinationFirewallGroups []types.OpenApiReference `json:"destinationFirewallGroups,omitempty"`
	// ApplicationPortProfiles contains a list of references to Application Port Profiles. Empty list means 'Any'
	ApplicationPortProfiles []types.OpenApiReference `json:"applicationPortProfiles,omitempty"`
	// IpProtocol 'IPV4', 'IPV6', 'IPV4_IPV6'
	IpProtocol string `json:"ipProtocol"`
	Logging    bool   `json:"logging"`
	// Direction 'IN_OUT', 'OUT', 'IN'
	Direction string `json:"direction"`
	// Version of firewall rule. Must not be set when creating.
	Version *struct {
		// Version is incremented after each update
		Version *int `json:"version,omitempty"`
	} `json:"version,omitempty"`
}

type NsxtFirewallRuleContainerV2 struct {
	SystemRules      []*NsxtFirewallRuleV2 `json:"systemRules"`
	DefaultRules     []*NsxtFirewallRuleV2 `json:"defaultRules"`
	UserDefinedRules []*NsxtFirewallRuleV2 `json:"userDefinedRules"`
}

func resourceVcdNsxtFirewallRule() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceVcdNsxtFirewallRuleCreate,
		ReadContext:   resourceVcdNsxtFirewallRuleRead,
		UpdateContext: resourceVcdNsxtFirewallRuleUpdate,
		DeleteContext: resourceVcdNsxtFirewallRuleDelete,
		Importer: &schema.ResourceImporter{
			StateContext: resourceVcdNsxtFirewallRuleImport,
		},

		Schema: map[string]*schema.Schema{
			"org": {
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: true,
				Description: "The name of organization to use, optional if defined at provider " +
					"level. Useful when connected as sysadmin working across different organizations",
			},
			"edge_gateway_id": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Edge Gateway ID in which Firewall Rule are located",
			},
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Firewall Rule name",
			},
			"action": {
				Type:         schema.TypeString,
				Required:     true,
				Description:  "Defines if the rule should 'ALLOW', 'DROP' or 'REJECT' matching traffic",
				ValidateFunc: validation.StringInSlice([]string{"ALLOW", "DROP", "REJECT"}, false),
			},
			"enabled": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
				Description: "Defined if Firewall Rule is active",
			},
			"logging": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Defines if matching traffic should be logged",
			},
			"direction": {
				Type:         schema.TypeString,
				Required:     true,
				Description:  "Direction on which Firewall Rule applies (One of 'IN', 'OUT', 'IN_OUT')",
				ValidateFunc: validation.StringInSlice([]string{"IN", "OUT", "IN_OUT"}, false),
			},
			"ip_protocol": {
				Type:         schema.TypeString,
				Required:     true,
				Description:  "Firewall Rule Protocol (One of 'IPV4', 'IPV6', 'IPV4_IPV6')",
				ValidateFunc: validation.StringInSlice([]string{"IPV4", "IPV6", "IPV4_IPV6"}, false),
			},
			"source_ids": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "A set of Source Firewall Group IDs (IP Sets or Security Groups). Leaving it empty means 'Any'",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"destination_ids": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "A set of Destination Firewall Group IDs (IP Sets or Security Groups). Leaving it empty means 'Any'",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"app_port_profile_ids": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "A set of Application Port Profile IDs. Leaving it empty means 'Any'",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"above_rule_id": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: "ID of the rule above which this rule should be created",
			},
		},
	}
}

func resourceVcdNsxtFirewallRuleCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	vcdClient := meta.(*VCDClient)
	orgName := d.Get("org").(string)
	edgeGatewayId := d.Get("edge_gateway_id").(string)

	// Confirm Edge Gateway exists and we have access
	_, err := vcdClient.GetNsxtEdgeGatewayById(orgName, edgeGatewayId)
	if err != nil {
		return diag.Errorf("error retrieving Edge Gateway: %s", err)
	}

	rule := getNsxtFirewallRuleFromSchema(d)

	endpoint, err := vcdClient.Client.OpenApiBuildEndpoint(fmt.Sprintf("%sedgeGateways/%s/firewall/rules/", types.OpenApiPathVersion2_0_0, edgeGatewayId))
	minimumApiVersion := "39.1"
	if err != nil {
		return diag.FromErr(err)
	}

	// This API endpoints returns the wrong owner object. We can get the correct ID from the task details.
	task, err := vcdClient.Client.OpenApiPostItemAsync(minimumApiVersion, endpoint, nil, rule)
	if err != nil {
		return diag.FromErr(err)
	}

	err = task.WaitTaskCompletion()
	if err != nil {
		return diag.FromErr(err)
	}

	returnReq := &NsxtFirewallRuleV2{}
	returnReq.ID = task.Task.Details

	d.SetId(returnReq.ID)

	return resourceVcdNsxtFirewallRuleRead(ctx, d, meta)
}

func resourceVcdNsxtFirewallRuleRead(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	vcdClient := meta.(*VCDClient)
	edgeGatewayId := d.Get("edge_gateway_id").(string)
	ruleId := d.Id()

	if ruleId == "" {
		return diag.Errorf("empty Firewall Rule ID")
	}

	endpoint := fmt.Sprintf(types.OpenApiPathVersion2_0_0+types.OpenApiEndpointNsxtFirewallRules, edgeGatewayId)
	minimumApiVersion := "39.1"

	urlRef, err := vcdClient.Client.OpenApiBuildEndpoint(fmt.Sprintf(endpoint+"/%s", ruleId))
	if err != nil {
		return diag.FromErr(err)
	}

	rule := &NsxtFirewallRuleV2{}

	err = vcdClient.Client.OpenApiGetItem(minimumApiVersion, urlRef, nil, rule, nil)
	if err != nil {
		if govcd.ContainsNotFound(err) {
			d.SetId("")
			return nil
		}
		return diag.FromErr(err)
	}

	setNsxtFirewallRuleToSchema(d, rule)
	return nil
}

func resourceVcdNsxtFirewallRuleUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	vcdClient := meta.(*VCDClient)
	orgName := d.Get("org").(string)
	edgeGatewayId := d.Get("edge_gateway_id").(string)
	ruleId := d.Id()

	_, err := vcdClient.GetNsxtEdgeGatewayById(orgName, edgeGatewayId)
	if err != nil {
		return diag.Errorf("error retrieving Edge Gateway: %s", err)
	}
	rule := getNsxtFirewallRuleFromSchema(d)
	rule.ID = ruleId

	endpoint := fmt.Sprintf(types.OpenApiPathVersion2_0_0+types.OpenApiEndpointNsxtFirewallRules, edgeGatewayId)
	minimumApiVersion := "39.1"

	urlRef, err := vcdClient.Client.OpenApiBuildEndpoint(fmt.Sprintf(endpoint+"/%s", ruleId))
	if err != nil {
		return diag.FromErr(err)
	}

	existingRule := &NsxtFirewallRuleV2{}
	err = vcdClient.Client.OpenApiGetItem(minimumApiVersion, urlRef, nil, existingRule, nil)
	if err != nil {
		return diag.FromErr(err)
	}
	rule.Version = existingRule.Version

	returnReq := &NsxtFirewallRuleV2{}
	err = vcdClient.Client.OpenApiPutItem(minimumApiVersion, urlRef, nil, rule, returnReq, nil)
	if err != nil {
		return diag.FromErr(err)
	}

	return resourceVcdNsxtFirewallRuleRead(ctx, d, meta)
}

func resourceVcdNsxtFirewallRuleDelete(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	vcdClient := meta.(*VCDClient)
	orgName := d.Get("org").(string)
	edgeGatewayId := d.Get("edge_gateway_id").(string)
	ruleId := d.Id()

	_, err := vcdClient.GetNsxtEdgeGatewayById(orgName, edgeGatewayId)
	if err != nil {
		if govcd.ContainsNotFound(err) {
			return nil
		}
		return diag.Errorf("error retrieving Edge Gateway: %s", err)
	}

	endpoint, err := vcdClient.Client.OpenApiBuildEndpoint(fmt.Sprintf("%sedgeGateways/%s/firewall/rules/%s", types.OpenApiPathVersion2_0_0, edgeGatewayId, ruleId))
	minimumApiVersion := "39.1"
	if err != nil {
		return diag.FromErr(err)
	}

	err = vcdClient.Client.OpenApiDeleteItem(minimumApiVersion, endpoint, nil, nil)
	if err != nil {
		if govcd.ContainsNotFound(err) {
			return nil
		}
		return diag.FromErr(err)
	}

	return nil
}

func resourceVcdNsxtFirewallRuleImport(ctx context.Context, d *schema.ResourceData, meta interface{}) ([]*schema.ResourceData, error) {
	parts := splitImportId(d.Id())

	if len(parts) == 3 {
		orgName := parts[0]
		edgeName := parts[1]
		ruleName := parts[2]

		vcdClient := meta.(*VCDClient)
		org, err := vcdClient.GetOrgByName(orgName)
		if err != nil {
			return nil, fmt.Errorf("error retrieving Org '%s': %s", orgName, err)
		}

		edge, err := org.GetNsxtEdgeGatewayByName(edgeName)
		if err != nil {
			return nil, fmt.Errorf("error retrieving Edge Gateway '%s': %s", edgeName, err)
		}

		endpoint, err := vcdClient.Client.OpenApiBuildEndpoint(fmt.Sprintf("%sedgeGateways/%s/firewall/rules", types.OpenApiPathVersion2_0_0, edge.EdgeGateway.ID))
		if err != nil {
			return nil, err
		}

		var container *NsxtFirewallRuleContainerV2 = &NsxtFirewallRuleContainerV2{}

		err = vcdClient.Client.OpenApiGetItem("39.1", endpoint, nil, container, nil)
		if err != nil {
			return nil, fmt.Errorf("error retrieving NSX-T Firewall Rules: %s", err)
		}

		var foundRule *NsxtFirewallRuleV2

		// Only search in UserDefinedRules as we likely only manage those
		for _, rule := range container.UserDefinedRules {
			if rule.Name == ruleName {
				foundRule = rule
				break
			}
		}

		if foundRule == nil {
			return nil, fmt.Errorf("could not find firewall rule with name '%s' in edge gateway '%s'", ruleName, edgeName)
		}

		dSet(d, "org", orgName)
		dSet(d, "edge_gateway_id", edge.EdgeGateway.ID)
		d.SetId(foundRule.ID)

		return []*schema.ResourceData{d}, nil
	}

	if len(parts) != 2 {
		return nil, fmt.Errorf("import ID must be in format 'edge_gateway_id.rule_id' or 'org.edge_name.rule_name'")
	}

	dSet(d, "edge_gateway_id", parts[0])
	d.SetId(parts[1])

	return []*schema.ResourceData{d}, nil
}

func splitImportId(id string) []string {
	return strings.Split(id, ImportSeparator)
}

func getNsxtFirewallRuleFromSchema(d *schema.ResourceData) *NsxtFirewallRuleV2 {
	rule := &NsxtFirewallRuleV2{
		Name:        d.Get("name").(string),
		ActionValue: d.Get("action").(string),
		Active:      d.Get("enabled").(bool),
		Logging:     d.Get("logging").(bool),
		Direction:   d.Get("direction").(string),
		IpProtocol:  d.Get("ip_protocol").(string),
	}

	if v, ok := d.GetOk("source_ids"); ok {
		rule.SourceFirewallGroups = convertSliceOfStringsToOpenApiReferenceIds(convertSchemaSetToSliceOfStrings(v.(*schema.Set)))
	}

	if v, ok := d.GetOk("destination_ids"); ok {
		rule.DestinationFirewallGroups = convertSliceOfStringsToOpenApiReferenceIds(convertSchemaSetToSliceOfStrings(v.(*schema.Set)))
	}

	if v, ok := d.GetOk("app_port_profile_ids"); ok {
		rule.ApplicationPortProfiles = convertSliceOfStringsToOpenApiReferenceIds(convertSchemaSetToSliceOfStrings(v.(*schema.Set)))
	}

	return rule
}

func setNsxtFirewallRuleToSchema(d *schema.ResourceData, rule *NsxtFirewallRuleV2) {
	dSet(d, "name", rule.Name)
	dSet(d, "action", rule.ActionValue)
	dSet(d, "enabled", rule.Active)
	dSet(d, "logging", rule.Logging)
	dSet(d, "direction", rule.Direction)
	dSet(d, "ip_protocol", rule.IpProtocol)

	if err := d.Set("source_ids", convertStringsToTypeSet(extractIdsFromOpenApiReferences(rule.SourceFirewallGroups))); err != nil {
		fmt.Printf("error setting source_ids in schema: %s", err)
	}
	if err := d.Set("destination_ids", convertStringsToTypeSet(extractIdsFromOpenApiReferences(rule.DestinationFirewallGroups))); err != nil {
		fmt.Printf("error setting destination_ids in schema: %s", err)
	}
	if err := d.Set("app_port_profile_ids", convertStringsToTypeSet(extractIdsFromOpenApiReferences(rule.ApplicationPortProfiles))); err != nil {
		fmt.Printf("error setting app_port_profile_ids in schema: %s", err)
	}
}
