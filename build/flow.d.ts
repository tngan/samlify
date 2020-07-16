export interface FlowResult {
    samlContent: string;
    extract: any;
}
export declare function flow(options: any): Promise<FlowResult>;
