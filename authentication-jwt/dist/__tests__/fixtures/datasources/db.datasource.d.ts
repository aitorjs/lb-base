import { juggler } from '@loopback/repository';
export declare class DbDataSource extends juggler.DataSource {
    static dataSourceName: string;
    static readonly defaultConfig: {
        name: string;
        connector: string;
    };
    constructor(dsConfig?: object);
}
