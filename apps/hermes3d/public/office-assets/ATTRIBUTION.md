# Hermes3D Office Assets & Third-Party Attribution

All visual, 3D model, lighting, and UI assets shipped under `apps/hermes3d` comply with OSI-approved or public-domain-equivalent open-source licenses.

## 1. Upstream Hermes3D Studio & 2D/3D Workspace Engine
- **Project:** [`iamlukethedev/Hermes3D`](https://github.com/iamlukethedev/Hermes3D)
- **License:** MIT License (`LICENSE`)
- **Scope:** Base 3D React Three Fiber / Three.js office workspace, procedural 2D Gather-style Phaser pixel office (`src/features/pixel-office/**`), gateway proxy transport, and studio UI components.

## 2. 3D Low-Poly Office Furniture Models (`public/office-assets/models/furniture/*.glb`)
- **Asset Pack:** **Kenney Furniture Kit** (`https://kenney.nl/assets/furniture-kit`)
- **Author:** Kenney (`Kenney Vleugels`)
- **License:** Creative Commons Zero v1.0 Universal (**CC0-1.0** — Public Domain Dedication)
- **Files Covered (`17` GLB meshes):**
  - `bookcaseClosed.glb`
  - `chairDesk.glb`
  - `chairModernCushion.glb`
  - `computerScreen.glb`
  - `desk.glb`
  - `deskCorner.glb`
  - `kitchenCabinet.glb`
  - `kitchenCoffeeMachine.glb`
  - `kitchenFridgeSmall.glb`
  - `lampRoundFloor.glb`
  - `loungeDesignChair.glb`
  - `loungeSofa.glb`
  - `plantSmall1.glb`
  - `pottedPlant.glb`
  - `table.glb`
  - `tableCoffee.glb`
  - `tableRound.glb`

## 3. HDRI Environment Lighting Map (`public/office-assets/env/office_env_1k.hdr`)
- **Asset:** `office_env_1k.hdr` (`1K` equirectangular Radiance HDRI environment reflection/lighting map, Poly Haven CC0 indoor studio/office lighting)
- **License:** Creative Commons Zero v1.0 Universal (**CC0-1.0** — Public Domain Dedication)

## 4. Deterministic SVG & 3D Procedural Avatars (`src/lib/avatars/`)
- **Implementation:** First-party deterministic SVG generator (`src/lib/avatars/multiavatar.ts`) and procedural 3D character profile system (`src/lib/avatars/profile.ts`).
- **License:** MIT License (`LICENSE`)
- **Supply-Chain Hygiene Note:** All avatar SVGs and 3D character meshes are generated procedurally by first-party MIT code (`src/lib/avatars/multiavatar.ts` and `src/lib/avatars/profile.ts`) with zero non-OSI third-party avatar vendor scripts.
