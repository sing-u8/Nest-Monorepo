export interface DomainEntity<T = any> {
	getId(): string;
	equals(entity: T): boolean;
	toJSON(): Record<string, any>;
}

export interface ValueObject<T = any> {
	equals(vo: T): boolean;
	getValue(): any;
	toJSON(): Record<string, any>;
}

// #question: DomainEvent와 ValueObject의 차이점은?
// DomainEvent는 시스템에서 발생한 사건을 나타내고, ValueObject는 도메인 내에서 특정 값을 나타냅니다.
// DomainEvent는 시간과 관련된 정보를 포함하고,
// ValueObject는 상태나 속성을 나타내는 불변 객체입니다.
export interface DomainEvent {
	occurredOn: Date;
	getAggregateId(): string;
	getEventType(): string;
}

export interface Repository<T> {
	save(entity: T): Promise<T>;
	findById(id: string | ValueObject): Promise<T | null>;
	delete(id: string | ValueObject): Promise<void>;
}

export interface PaginationOptions {
	page: number;
	limit: number;
	sortBy?: string;
	sortOrder?: "ASC" | "DESC";
}

// #question: page, total page가 필요한 이유는?
export interface PaginatedResult<T> {
	items: T[];
	total: number;
	page: number;
	limit: number;
	totalPages: number;
	hasNext: boolean;
	hasPrevious: boolean;
}

export interface SearchOptions extends PaginationOptions {
	searchTerm?: string;
	filters?: Record<string, any>;
}

export interface GetUsersOptions extends PaginationOptions {
	isActive?: boolean;
	provider?: string;
	isEmailVerified?: boolean;
	search?: string;
}
