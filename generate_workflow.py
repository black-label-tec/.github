from pathlib import Path

ROOT=Path(__file__).parent
script=(ROOT/'integrity.py').read_text()
workflow='''name: Black Label source integrity
on:
  workflow_call:
permissions:
  contents: read
jobs:
  integrity:
    name: Source integrity (not product acceptance)
    runs-on: ubuntu-24.04
    timeout-minutes: 10
    steps:
      - name: Check out candidate
        uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262
        with:
          fetch-depth: 0
          persist-credentials: false
      - name: Verify committed changes and write receipt
        env:
          BASE_SHA: ${{ github.event.pull_request.base.sha || github.event.merge_group.base_sha || github.event.before }}
        shell: bash
        run: |
          python3 - --output "$RUNNER_TEMP/source-integrity.json" <<'PY'
'''+''.join('          '+line+'\n' for line in script.splitlines())+'''          PY
      - name: Retain evidence, including failures
        if: always()
        uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9
        with:
          name: source-integrity-${{ github.run_id }}-${{ github.run_attempt }}
          path: ${{ runner.temp }}/source-integrity.json
          if-no-files-found: error
          retention-days: 30
'''
dest=ROOT/'.github/workflows/source-integrity.yml'
dest.parent.mkdir(parents=True,exist_ok=True);dest.write_text(workflow)
