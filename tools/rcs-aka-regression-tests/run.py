"""Compile actual service code with synthetic Android adapters; no network calls."""
from pathlib import Path
import argparse, os, subprocess, sys
p=argparse.ArgumentParser();p.add_argument('--compiler-dir',type=Path,required=True);args=p.parse_args()
root=Path(__file__).resolve().parent;repo=root.parents[1]
source=repo/'play-services-constellation/core/src/main/kotlin/org/microg/gms/constellation/core/verification/ts43'
libs=args.compiler_dir.resolve();jars=sorted(libs.glob('*.jar'))
if not jars:raise SystemExit('Point --compiler-dir at the documented Kotlin compiler JARs.')
cp=os.pathsep.join(map(str,jars));stdlib=os.pathsep.join(str(x) for x in jars if x.name.startswith(('kotlin-stdlib-','annotations-')))
output=root/'output';output.mkdir(exist_ok=True)
cmd=['java','-Xmx512m','-XX:ActiveProcessorCount=2','-cp',cp,'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler','-no-stdlib','-no-reflect','-jvm-target','1.8','-classpath',stdlib,'-d',str(output/'tests.jar')]
cmd += [str(source/n) for n in ['EapAkaService.kt','Fips186Prf.kt']]
if (source/'EapAkaChallenge.kt').exists():cmd.append(str(source/'EapAkaChallenge.kt'))
cmd += [str(x) for x in root.glob('*.kt')]
subprocess.run(cmd,check=True,timeout=120)
r=subprocess.run(['java','-Xmx256m','-cp',str(output/'tests.jar')+os.pathsep+stdlib,'tests.MainKt'],timeout=30)
raise SystemExit(r.returncode)
