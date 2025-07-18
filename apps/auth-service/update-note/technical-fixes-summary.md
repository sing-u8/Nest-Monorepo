# 🔧 기술적 수정 사항 요약

**작성일**: 2025-07-18  
**대상**: 개발팀 기술 리뷰  

## 🚨 해결된 핵심 문제들

### 1. **NestJS 모듈 Export 문제**

```typescript
// ❌ 문제가 있던 코드
@Module({
  exports: [
    AuthController,        // 컨트롤러 export 시도
    UserController,        // 컨트롤러 export 시도
    AuthApplicationService,
    UserApplicationService,
  ]
})
```

```typescript
// ✅ 수정된 코드
@Module({
  exports: [
    // 컨트롤러는 export 불필요
    // Application Services는 AuthApplicationModule에서 제공
  ]
})
```

**에러 메시지**: `UnknownExportException: Nest cannot export a provider/module that is not a part of the currently processed module`

---

### 2. **의존성 주입 토큰 문제**

```typescript
// ❌ 문제가 있던 코드
constructor(
  private readonly userRepository: IUserRepository, // 인터페이스 직접 주입
  private readonly passwordDomainService: PasswordDomainService,
) {}
```

```typescript
// ✅ 수정된 코드
constructor(
  @Inject(USER_REPOSITORY_TOKEN) // 토큰을 통한 주입
  private readonly userRepository: IUserRepository,
  private readonly passwordDomainService: PasswordDomainService,
) {}
```

**에러 메시지**: `UnknownDependenciesException: Nest can't resolve dependencies of the PasswordApplicationService (?, PasswordDomainService)`

---

### 3. **모듈 계층 의존성 구조 문제**

```typescript
// ❌ 문제가 있던 코드
@Module({
  imports: [AuthInfrastructureModule],
  providers: [
    AuthApplicationService,  // 잘못된 계층에서 제공
    UserApplicationService,  // 잘못된 계층에서 제공
  ]
})
```

```typescript
// ✅ 수정된 코드
@Module({
  imports: [
    AuthApplicationModule,    // Application 계층 의존
    AuthInfrastructureModule, // Infrastructure 계층 의존
  ],
  providers: [
    // Application Service는 직접 제공하지 않음
    // 글로벌 필터/인터셉터만 제공
  ]
})
```

**에러 메시지**: `UnknownDependenciesException: Nest can't resolve dependencies of the AuthApplicationService`

---

## 📂 수정된 파일 목록

### 1. **모듈 구조 수정**
- `apps/auth-service/src/auth/presentation/auth-presentation.module.ts`
- `apps/auth-service/src/auth/application/auth-application.module.ts`

### 2. **의존성 주입 패턴 수정**
- `apps/auth-service/src/auth/application/service/password.service.ts`
- `apps/auth-service/src/auth/application/service/social-auth.service.ts`

### 3. **프로젝트 가이드라인 업데이트**
- `.cursor/rules/auth-service-rules.md`

---

## 🎯 수정 사항별 상세 분석

### **문제 1: NestJS 모듈 Export 패턴**

#### 원인
- NestJS에서 컨트롤러는 HTTP 라우팅을 담당하므로 다른 모듈에서 주입받을 필요가 없음
- Export는 다른 모듈에서 사용할 Provider만 대상으로 함

#### 해결 원칙
```typescript
// 📋 NestJS Export 규칙
✅ Export 해야 하는 것:
   - Services (다른 모듈에서 주입받아 사용)
   - Providers (의존성 주입이 필요한 경우)
   - Configuration (설정 관련 클래스)

❌ Export 하지 않는 것:
   - Controllers (HTTP 라우팅 담당)
   - Global Filters/Interceptors (APP_FILTER, APP_INTERCEPTOR 토큰 사용)
   - Guards (데코레이터로 사용되는 경우)
```

---

### **문제 2: TypeScript 인터페이스 vs 런타임 토큰**

#### 원인
- TypeScript 인터페이스는 컴파일 시점에만 존재
- 런타임에서는 인터페이스 정보가 사라짐
- NestJS DI 컨테이너는 런타임에 토큰을 찾아야 함

#### 해결 패턴
```typescript
// 📋 인터페이스 의존성 주입 패턴
1. 인터페이스 정의: IUserRepository
2. 토큰 정의: USER_REPOSITORY_TOKEN
3. 구현체 등록: { provide: USER_REPOSITORY_TOKEN, useClass: UserTypeormRepository }
4. 토큰으로 주입: @Inject(USER_REPOSITORY_TOKEN)
```

---

### **문제 3: 클린 아키텍처 계층 분리**

#### 원인
- Presentation 계층이 Application Service를 직접 제공
- 클린 아키텍처 의존성 방향 원칙 위반
- 각 계층의 책임 경계 모호

#### 해결 원칙
```typescript
// 📋 클린 아키텍처 계층별 책임
Presentation Layer:
  - 컨트롤러 (HTTP 요청/응답)
  - 글로벌 필터/인터셉터
  - 요청/응답 DTO

Application Layer:
  - 애플리케이션 서비스
  - 도메인 서비스
  - 이벤트 핸들러
  - 애플리케이션 DTO

Infrastructure Layer:
  - 리포지토리 구현체
  - 외부 서비스 연동
  - 데이터베이스 엔티티
  - 설정 관리
```

---

## 🔍 학습된 베스트 프랙티스

### 1. **NestJS 모듈 설계 원칙**
```typescript
// 계층별 모듈 의존성 방향
AuthPresentationModule → AuthApplicationModule → AuthInfrastructureModule
                     → AuthInfrastructureModule (가드, 필터 등)
```

### 2. **의존성 주입 패턴**
```typescript
// 항상 인터페이스 + 토큰 조합 사용
@Inject(INTERFACE_TOKEN)
private readonly service: IService
```

### 3. **에러 디버깅 접근법**
```typescript
// 1. 에러 메시지에서 핵심 정보 추출
// 2. 의존성 체인 추적
// 3. 계층별 책임 확인
// 4. 토큰 등록 상태 확인
```

---

## 🚀 개선된 시스템 특징

### **안정성**
- 모든 의존성 주입 에러 해결
- 런타임 안정성 확보
- 타입 안전성 보장

### **유지보수성**
- 계층별 명확한 책임 분리
- 의존성 방향 일관성
- 확장 가능한 구조

### **성능**
- 불필요한 의존성 제거
- 효율적인 모듈 로딩
- 최적화된 DI 컨테이너 사용

---

## 📚 개발팀 가이드라인

### **새로운 서비스 추가 시**
1. 도메인 인터페이스 정의
2. 토큰 상수 정의
3. 인프라 구현체 작성
4. 애플리케이션 서비스에서 @Inject 사용

### **새로운 모듈 추가 시**
1. 계층별 모듈 분리
2. 의존성 방향 확인
3. Export 대상 신중히 선택
4. 컨트롤러는 export 하지 않음

### **문제 해결 프로세스**
1. 에러 메시지 정확히 분석
2. 의존성 체인 추적
3. 토큰 등록 상태 확인
4. 계층별 책임 검토

---

**📅 작성일**: 2025-07-18  
**🔄 다음 기술 리뷰**: 새로운 기능 추가 시  
**📧 문의**: 시스템 아키텍트